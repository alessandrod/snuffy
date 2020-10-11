#![no_std]
#![no_main]
use redbpf_probes::helpers::gen;
use redbpf_probes::uprobe::prelude::*;
use snuffy_probes::snuffy::{
    AccessMode, Config, Connection, SSLBuffer, SSLFd, SSLHost, BUF_LEN, COMM_LEN,
    CONFIG_KEY, DNS, HOST_LEN,
};
use snuffy_probes::user_bindings::addrinfo;

const REQ_OP_WRITE: u32 = 1;

program!(0xFFFFFFFE, "GPL");

#[map("config")]
static mut config: HashMap<usize, Config> = HashMap::with_max_entries(1);

#[map("dns")]
static mut dns_events: PerfMap<DNS> = PerfMap::with_max_entries(1024);

#[map("ssl_fd")]
static mut ssl_fd_events: PerfMap<SSLFd> = PerfMap::with_max_entries(1024);

#[map("ssl_buffer")]
static mut ssl_buffer_events: PerfMap<SSLBuffer> = PerfMap::with_max_entries(1024);

#[map("connection")]
static mut connection_events: PerfMap<Connection> = PerfMap::with_max_entries(1024);

#[map("dns_hosts")]
static mut dns_hosts: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024);

#[map("ssl_args")]
static mut ssl_args: HashMap<u64, SSLArgs> = HashMap::with_max_entries(1024);

#[map("nss_ssl_contexts")]
static mut nss_ssl_contexts: HashMap<usize, u8> = HashMap::with_max_entries(1024);

#[map("ssl_host")]
static mut ssl_host_events: PerfMap<SSLHost> = PerfMap::with_max_entries(1024);

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
        pid: current_pid(),
        comm: current_comm(),
        addr: addr.sin_addr()?.s_addr()? as u64,
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
        pid: current_pid(),
        comm: current_comm(),
        fd: fd as u64,
        addr: addr.sin_addr()?.s_addr()?,
        port: u16::from_be(addr.sin_port()?) as u32,
    };

    unsafe {
        connection_events.insert(regs.ctx, &conn);
    }

    None
}

#[uprobe]
fn SSL_set_fd(regs: Registers) {
    let ssl_ctx = regs.parm1() as usize;
    let fd = regs.parm2() as i32;

    if fd < 0 {
        return;
    }

    unsafe {
        ssl_fd_events.insert(
            regs.ctx,
            &SSLFd {
                pid: current_pid(),
                comm: current_comm(),
                ssl_ctx,
                fd: fd as usize,
            },
        )
    }
}

fn do_read(regs: Registers) {
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

fn do_read_ret(regs: Registers) {
    let len = regs.rc() as i32;

    if len < 0 {
        return;
    }
    let args = unsafe { ssl_args.get(&bpf_get_current_pid_tgid()) };
    if let Some(SSLArgs { ssl, buf }) = args {
        output_buf(regs, *ssl, AccessMode::Read, *buf, len as u32);
        unsafe { ssl_args.delete(&bpf_get_current_pid_tgid()) };
    }
}

fn do_write(regs: Registers) {
    let ssl = regs.parm1() as usize;
    let buf = regs.parm2() as usize;
    let len = regs.parm3() as i32;
    if len <= 0 {
        return;
    }
    if !is_target_command() {
        return;
    }

    output_buf(regs, ssl, AccessMode::Write, buf, len as u32);
}

#[uprobe]
fn SSL_read(regs: Registers) {
    do_read(regs);
}

#[uretprobe]
fn SSL_read_ret(regs: Registers) {
    do_read_ret(regs);
}

#[uprobe]
fn SSL_write(regs: Registers) {
    do_write(regs);
}

#[uprobe]
fn SSL_SetURL(regs: Registers) {
    let ssl_ctx = regs.parm1() as usize;
    let host = regs.parm2() as *const c_void;

    let mut event = SSLHost {
        pid: current_pid(),
        comm: current_comm(),
        ssl_ctx,
        host: [0; HOST_LEN],
    };

    unsafe { bpf_probe_read_str(event.host.as_mut_ptr() as *mut _, HOST_LEN as i32, host) };

    unsafe {
        let value = 1;
        nss_ssl_contexts.set(&ssl_ctx, &value);
        ssl_host_events.insert(regs.ctx, &event);
    }
}

#[uprobe]
fn nss_read(regs: Registers) {
    let ssl_ctx = regs.parm1() as usize;
    if unsafe { nss_ssl_contexts.get(&ssl_ctx) }.is_some() {
        do_read(regs);
    }
}

#[uretprobe]
fn nss_read_ret(regs: Registers) {
    let len = regs.rc();
    // 0 means connection closed
    if len > 0 {
        do_read_ret(regs);
    }
}

#[uprobe]
fn nss_write(regs: Registers) {
    let ssl_ctx = regs.parm1() as usize;
    if unsafe { nss_ssl_contexts.get(&ssl_ctx) }.is_some() {
        do_write(regs);
    }
}

fn output_buf(regs: Registers, ssl_ctx: usize, mode: AccessMode, buf_addr: usize, len: u32) {
    let mut buf = SSLBuffer {
        pid: current_pid(),
        comm: current_comm(),
        ssl_ctx,
        mode,
        len: len as usize,
        chunk_len: 0,
        chunk: [0u8; BUF_LEN],
    };

    let len = len as usize;
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

fn is_target_command() -> bool {
    let comm = bpf_get_current_comm();
    let key = CONFIG_KEY;
    let conf = unsafe { config.get(&key) };
    conf.map(|c| {
        if c.target_comm_set == 0 {
            return true;
        }

        let cmd = unsafe { core::slice::from_raw_parts(comm.as_ptr(), COMM_LEN) };
        cmd[..COMM_LEN] == c.target_comm
    })
    .unwrap_or(false)
}

fn current_pid() -> u64 {
    (bpf_get_current_pid_tgid() >> 32) as u64
}

fn current_comm() -> [c_char; COMM_LEN] {
    let mut comm: [c_char; COMM_LEN] = [0; COMM_LEN];
    unsafe { gen::bpf_get_current_comm(&mut comm as *mut _ as *mut c_void, COMM_LEN as u32) };
    comm
}
