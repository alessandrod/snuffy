use cty::c_char;

pub const CONFIG_KEY: usize = 1;
pub const COMM_LEN: usize = 16;
pub const BUF_LEN: usize = 368;
pub const HOST_LEN: usize = 256;

#[repr(C)]
#[derive(Clone)]
pub struct Config {
    pub target_comm_set: usize,
    pub target_comm: [c_char; COMM_LEN],
}

#[repr(C)]
pub struct DNS {
    pub pid: u64,
    pub comm: [c_char; COMM_LEN],
    pub addr: u64,
    pub host: [c_char; HOST_LEN],
}
#[repr(C)]
#[derive(Clone)]
pub struct Connection {
    pub pid: u64,
    pub comm: [c_char; COMM_LEN],
    pub fd: u64,
    pub addr: u32,
    pub port: u32,
}

#[repr(C)]
pub struct SSLBuffer {
    pub pid: u64,
    pub comm: [c_char; COMM_LEN],
    pub ssl_ctx: usize,
    pub mode: AccessMode,
    pub len: usize,
    pub chunk_len: usize,
    pub chunk: [u8; BUF_LEN],
}

#[repr(C)]
pub struct SSLHost {
    pub pid: u64,
    pub comm: [c_char; COMM_LEN],
    pub ssl_ctx: usize,
    pub host: [c_char; HOST_LEN],
}

#[repr(C)]
pub struct SSLFd {
    pub pid: u64,
    pub comm: [c_char; COMM_LEN],
    pub ssl_ctx: usize,
    pub fd: usize,
}

#[repr(u64)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum AccessMode {
    Read,
    Write,
}
