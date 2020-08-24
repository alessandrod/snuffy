#![no_std]
#![no_main]
use probes::snuffy::{
    AccessMode, Config, Connection, SSLBuffer, BUF_LEN, COMM_LEN, CONFIG_KEY, DNS, HOST_LEN,
};
use probes::user_bindings::addrinfo;
use redbpf_probes::helpers::gen;
use redbpf_probes::uprobe::prelude::*;

const REQ_OP_WRITE: u32 = 1;

program!(0xFFFFFFFE, "GPL");

#[map("config")]
static mut config: HashMap<usize, Config> = HashMap::with_max_entries(1);

#[map("dns")]
static mut dns_events: PerfMap<DNS> = PerfMap::with_max_entries(1024);

#[map("ssl_buffer")]
static mut ssl_buffer_events: PerfMap<SSLBuffer> = PerfMap::with_max_entries(1024);

#[map("connection")]
static mut connection_events: PerfMap<Connection> = PerfMap::with_max_entries(1024);

#[map("dns_hosts")]
static mut dns_hosts: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024);

#[map("fd_connections")]
static mut connections: HashMap<i32, Connection> = HashMap::with_max_entries(1024);

#[map("ssl_args")]
static mut ssl_args: HashMap<u64, SSLArgs> = HashMap::with_max_entries(1024);

const SYS_CONNECT: i32 = 42;

struct SSLArgs {
    ssl: usize,
    buf: usize,
}

#[uprobe]
fn getaddrinfo(regs: Registers) {
    if !is_target_command() {
        return;
    }

    let tid = bpf_get_current_pid_tgid();
    unsafe { dns_hosts.set(&tid, &(regs.parm1(), regs.parm4())) };
}

#[uretprobe]
fn getaddrinfo_ret(regs: Registers) {
    let _ = do_getaddrinfo_ret(regs);
}

fn do_getaddrinfo_ret(regs: Registers) -> Option<()> {
    let tid = bpf_get_current_pid_tgid();
    let (node, ret_addr) = unsafe { *dns_hosts.get(&tid)? };

    let info = unsafe { &*bpf_probe_read(ret_addr as *const *const addrinfo).ok()? };
    if info.ai_family()? as u32 != AF_INET {
        return None;
    }
    let addr = unsafe { &*(info.ai_addr()? as *const sockaddr_in) };

    let mut dns = DNS {
        addr: addr.sin_addr()?.s_addr()?,
        host: [0; HOST_LEN],
    };

    unsafe {
        bpf_probe_read_str(
            dns.host.as_mut_ptr() as *mut _,
            HOST_LEN as i32,
            node as *const c_void,
        )
    };

    unsafe {
        dns_events.insert(regs.ctx, &dns);
    }

    None
}

#[uprobe]
fn connect(regs: Registers) {
    let _ = do_connect(regs);
}

fn do_connect(regs: Registers) -> Option<()> {
    let fd = regs.parm1() as i32;
    let addr = regs.parm2() as *const sockaddr;

    if unsafe { &*addr }.sa_family()? as u32 != AF_INET {
        return None;
    }

    if !is_target_command() {
        return None;
    }

    let addr = unsafe { &*(addr as *const sockaddr_in) };
    let conn = Connection {
        fd: fd as u64,
        addr: addr.sin_addr()?.s_addr()?,
        port: u16::from_be(addr.sin_port()?) as u32,
    };

    unsafe {
        connections.set(&fd, &conn);
        connection_events.insert(regs.ctx, &conn);
    }

    None
}

#[uprobe]
fn SSL_read(regs: Registers) {
    let ssl = regs.parm1() as usize;
    let buf = regs.parm2() as usize;
    let len = regs.parm3() as usize;
    if len <= 0 {
        return;
    }

    if is_target_command() {
        unsafe {
            ssl_args.set(&bpf_get_current_pid_tgid(), &SSLArgs { ssl, buf });
        }
    }
}

#[uretprobe]
fn SSL_read_ret(regs: Registers) {
    let len = regs.rc() as i32;
    if len < 0 {
        return;
    }
    let args = unsafe { ssl_args.get(&bpf_get_current_pid_tgid()) };
    if let Some(SSLArgs { ssl, buf }) = args {
        let fd = if extract_fds() {
            ssl_rbio(*ssl).and_then(bio_fd).ok()
        } else {
            None
        };
        output_buf(regs, *ssl, fd, AccessMode::Read, *buf, len as usize);
        unsafe { ssl_args.delete(&bpf_get_current_pid_tgid()) };
    }
}

#[uprobe]
fn SSL_write(regs: Registers) {
    let ssl = regs.parm1() as usize;
    let buf = regs.parm2() as usize;
    let len = regs.parm3() as i32;
    if len <= 0 {
        return;
    }
    if !is_target_command() {
        return;
    }

    let fd = if extract_fds() {
        ssl_wbio(ssl).and_then(bio_fd).ok()
    } else {
        None
    };
    output_buf(regs, ssl, fd, AccessMode::Write, buf, len as usize);
}

fn output_buf(
    regs: Registers,
    ssl_handle: usize,
    fd: Option<i32>,
    mode: AccessMode,
    buf_addr: usize,
    len: usize,
) {
    let mut buf = SSLBuffer {
        ssl_handle,
        fd: fd.unwrap_or(-1),
        mode,
        len,
        chunk_len: 0,
        chunk: [0u8; BUF_LEN],
    };

    let mut read = 0;
    let read_len = BUF_LEN;
    for _ in 0..110 {
        let err = unsafe {
            gen::bpf_probe_read(
                buf.chunk.as_mut_ptr() as *mut _,
                read_len as u32,
                (buf_addr + read) as *const c_void,
            )
        };
        if err < 0 {
            break;
        }
        let left = len - read;
        if left > read_len {
            read += read_len;
            buf.chunk_len = read_len;
        } else {
            buf.chunk_len = left;
            read = len;
        }

        unsafe { ssl_buffer_events.insert(regs.ctx, &buf) };

        if read == len {
            break;
        }
    }

    buf.chunk_len = 0;
    unsafe { ssl_buffer_events.insert(regs.ctx, &buf) };
}

fn ssl_rbio(ssl: usize) -> Result<*const c_void, i32> {
    unsafe { bpf_probe_read((ssl + 16) as *const *const c_void) }
}

fn ssl_wbio(ssl: usize) -> Result<*const c_void, i32> {
    unsafe { bpf_probe_read((ssl + 24) as *const *const c_void) }
}

fn bio_fd(bio: *const c_void) -> Result<i32, i32> {
    unsafe { bpf_probe_read((bio as usize + 48) as *const i32) }
}

fn is_target_command() -> bool {
    let comm = bpf_get_current_comm();
    let key = CONFIG_KEY;
    let conf = unsafe { config.get(&key) };
    conf.map(|c| {
        if c.target_comm_set == 0 {
            return true;
        }

        let cmd = unsafe { core::slice::from_raw_parts(comm.as_ptr() as *const u8, COMM_LEN) };
        cmd[..COMM_LEN] == c.target_comm
    })
    .unwrap_or(false)
}

fn extract_fds() -> bool {
    let key = CONFIG_KEY;
    unsafe { config.get(&key) }
        .map(|c| c.extract_fds == 1)
        .unwrap_or(false)
}
