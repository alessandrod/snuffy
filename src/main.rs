// Copyright 2020 Alessandro Decina
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::raw::c_char;
use std::str::FromStr;
use std::{cmp, fs, path::Path, ptr};

use anyhow::anyhow;
use futures::stream::StreamExt;
use hexdump::hexdump_iter;
use redbpf::{load::Loader, HashMap as BPFHashMap};
use serde::Deserialize;
use structopt::StructOpt;
use time::OffsetDateTime;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

use snuffy_probes::snuffy::{
    AccessMode, Config, Connection, SSLBuffer, SSLFd, SSLHost, COMM_LEN, CONFIG_KEY, DNS,
};

static TLS_LIBS: [&str; 2] = ["openssl", "nss"];

macro_rules! attach_uprobe {
    ($uprobe:ident, $name:literal, $target:expr, $offset:expr, $opts:ident) => {
        {
            let (fn_name, offset, target) = match $offset {
                Some(offset) => (None, offset, $opts.command.as_ref().unwrap().as_str()),
                None => (Some($name), 0, $target),
            };
            attach_uprobe!(@IMPL, $uprobe, $name, fn_name, offset, target, $opts.pid)
        }
    };

    ($uprobe:ident, $name:literal, $target:expr, $opts:ident) => {
        attach_uprobe!(@IMPL, $uprobe, $name, Some($name), 0, $target, $opts.pid)
    };

    (@IMPL, $uprobe:ident, $name:literal, $fn_name:expr, $offset:expr, $target:expr, $pid:expr) => {
        $uprobe
            .attach_uprobe($fn_name, $offset, $target, $pid)
            .map_err(|e| anyhow!("error attaching to `{}`: {:?}", $name, e))
    };
}

fn main() -> Result<(), anyhow::Error> {
    let mut opts = Opts::from_args();
    let target_libs: HashSet<String> = if !opts.libs.is_empty() {
        opts.libs.drain(..).collect()
    } else {
        TLS_LIBS.iter().cloned().map(String::from).collect()
    };

    let mut runtime = Runtime::new()?;
    let _ = runtime.block_on(async {
        let mut loader =
            Loader::load(probe_code()).map_err(|e| anyhow!("Error loading probes: {:?}", e))?;
        let target_comm_set = opts.command.is_some();
        let mut target_comm = [0u8; COMM_LEN];
        if let Some(command) = opts
            .command
            .as_ref()
            .and_then(|c| Path::new(c).file_name())
            .and_then(|c| c.to_str())
        {
            let len = cmp::min(command.len(), COMM_LEN);
            target_comm[..len].copy_from_slice(&command[..len].as_bytes());
        }

        let config = BPFHashMap::<usize, Config>::new(loader.map("config").unwrap()).unwrap();
        config.set(
            CONFIG_KEY,
            Config {
                target_comm_set: target_comm_set as usize,
                target_comm,
            },
        );

        let conf = opts.config.take().unwrap_or_default();
        let libssl = conf
            .openssl
            .libssl
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("libssl");
        let libssl3 = conf
            .nss
            .libssl3
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("libssl3");
        let libnspr4 = conf
            .nss
            .libnspr4
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("libnspr4");

        // attach the uprobes
        for uprobe in loader.uprobes_mut() {
            match uprobe.name().as_str() {
                "getaddrinfo" | "getaddrinfo_ret" => {
                    attach_uprobe!(uprobe, "getaddrinfo", "libc", opts)?;
                }
                "connect" => {
                    attach_uprobe!(uprobe, "connect", "libpthread", opts)?;
                }
                // OpenSSL
                "SSL_set_fd" if target_libs.contains("openssl") => {
                    attach_uprobe!(uprobe, "SSL_set_fd", libssl, conf.openssl.SSL_set_fd, opts)?;
                }
                "SSL_read" | "SSL_read_ret" if target_libs.contains("openssl") => {
                    attach_uprobe!(uprobe, "SSL_read", libssl, conf.openssl.SSL_read, opts)?;
                }
                "SSL_write" if target_libs.contains("openssl") => {
                    attach_uprobe!(uprobe, "SSL_write", libssl, conf.openssl.SSL_write, opts)?;
                }
                // NSS
                "SSL_SetURL" if target_libs.contains("nss") => {
                    attach_uprobe!(uprobe, "SSL_SetURL", libssl3, conf.nss.SSL_SetURL, opts)?;
                }
                "nss_read" | "nss_read_ret" if target_libs.contains("nss") => {
                    attach_uprobe!(uprobe, "PR_Read", libnspr4, conf.nss.PR_Read, opts)?;
                    attach_uprobe!(uprobe, "PR_Recv", libnspr4, conf.nss.PR_Recv, opts)?;
                    attach_uprobe!(uprobe, "PR_RecvFrom", libnspr4, conf.nss.PR_RecvFrom, opts)?;
                }
                "nss_write" if target_libs.contains("nss") => {
                    attach_uprobe!(uprobe, "PR_Write", libnspr4, conf.nss.PR_Write, opts)?;
                    attach_uprobe!(uprobe, "PR_Send", libnspr4, conf.nss.PR_Send, opts)?;
                }
                _ => continue,
            }
        }

        let mut state = ObservedState::new();
        let mut buffers = Buffers::new();
        tokio::spawn(async move {
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    match name.as_str() {
                        "dns" => {
                            let event = unsafe { ptr::read(event.as_ptr() as *const DNS) };
                            let host =
                                unsafe { CStr::from_ptr(event.host.as_ptr() as *const c_char) }
                                    .to_str()
                                    .unwrap();
                            let ip = Ipv4Addr::from(unsafe {
                                mem::transmute::<u32, [u8; 4]>(event.addr)
                            });
                            println!("{} Resolved {} to {}", now(), host, ip);
                            state.record_dns(host.to_string(), vec![ip]);
                        }
                        "connection" => {
                            let conn = unsafe { ptr::read(event.as_ptr() as *const Connection) };
                            let ip = Ipv4Addr::from(unsafe {
                                mem::transmute::<u32, [u8; 4]>(conn.addr)
                            });
                            let addr = SocketAddrV4::new(ip, conn.port as u16);
                            state.record_connection(conn.fd as i32, addr);
                            println!("{} Connected to {}", now(), state.format_address(&addr));
                        }
                        "ssl_fd" => {
                            let event = unsafe { ptr::read(event.as_ptr() as *const SSLFd) };
                            state.record_ssl_fd(event.ssl_ctx, event.fd as i32);
                        }
                        "ssl_host" => {
                            let event = unsafe { ptr::read(event.as_ptr() as *const SSLHost) };
                            let host =
                                unsafe { CStr::from_ptr(event.host.as_ptr() as *const c_char) }
                                    .to_str()
                                    .unwrap();
                            state.record_ssl_host(event.ssl_ctx, host.to_string());
                            println!(
                                "{} SSL context 0x{:x} connected to {}",
                                now(),
                                event.ssl_ctx,
                                host
                            );
                        }
                        "ssl_buffer" => {
                            let buf = unsafe { ptr::read(event.as_ptr() as *const SSLBuffer) };
                            if let Some(data) = buffers.push(&buf) {
                                let complete = if buf.len == data.len() {
                                    ""
                                } else {
                                    " (incomplete)"
                                };

                                let addr = state
                                    .lookup_ssl_fd(&buf.ssl_ctx)
                                    .and_then(|fd| state.address_by_fd(fd));
                                let addr = if let Some(addr) = addr {
                                    Some(state.format_address(&addr))
                                } else if let Some(host) = state.lookup_ssl_host(&buf.ssl_ctx) {
                                    Some(host.to_string())
                                } else {
                                    None
                                };
                                if buf.mode == AccessMode::Read {
                                    println!(
                                        "{} Read {} bytes{} {}(context: 0x{:x})",
                                        now(),
                                        data.len(),
                                        complete,
                                        addr.map(|a| format!("from {} ", a))
                                            .unwrap_or("".to_string()),
                                        buf.ssl_ctx
                                    );
                                } else {
                                    println!(
                                        "{} Write {} bytes{} {}(context: 0x{:x})",
                                        now(),
                                        data.len(),
                                        complete,
                                        addr.map(|a| format!("to {} ", a))
                                            .unwrap_or("".to_string()),
                                        buf.ssl_ctx
                                    );
                                }
                                if opts.hex_dump {
                                    for line in hexdump_iter(&data) {
                                        println!("{} {}", now(), line);
                                    }
                                }
                            }
                        }
                        _ => panic!("unexpected event"),
                    }
                }
            }
        });
        Ok::<(), anyhow::Error>(signal::ctrl_c().await?)
    })?;

    Ok(())
}
struct Buffers {
    buffers: HashMap<(usize, AccessMode), Vec<u8>>,
}

impl Buffers {
    fn new() -> Self {
        Buffers {
            buffers: HashMap::new(),
        }
    }

    fn push(&mut self, ssl_buf: &SSLBuffer) -> Option<Vec<u8>> {
        let buf = self
            .buffers
            .entry((ssl_buf.ssl_ctx, ssl_buf.mode))
            .or_insert_with(Vec::new);
        let len = ssl_buf.chunk_len;
        if len > 0 {
            buf.extend(&ssl_buf.chunk[..len]);
            None
        } else {
            Some(buf.drain(..).collect())
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct OpenSSLConfig {
    libssl: Option<String>,
    SSL_set_fd: Option<u64>,
    SSL_read: Option<u64>,
    SSL_write: Option<u64>,
}

impl Default for OpenSSLConfig {
    fn default() -> OpenSSLConfig {
        OpenSSLConfig {
            libssl: None,
            SSL_set_fd: None,
            SSL_read: None,
            SSL_write: None,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct NSSConfig {
    libssl3: Option<String>,
    libnspr4: Option<String>,
    SSL_SetURL: Option<u64>,
    PR_Read: Option<u64>,
    PR_Recv: Option<u64>,
    PR_RecvFrom: Option<u64>,
    PR_Write: Option<u64>,
    PR_Send: Option<u64>,
}

impl Default for NSSConfig {
    fn default() -> NSSConfig {
        NSSConfig {
            libssl3: None,
            libnspr4: None,
            SSL_SetURL: None,
            PR_Read: None,
            PR_Recv: None,
            PR_RecvFrom: None,
            PR_Write: None,
            PR_Send: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    openssl: OpenSSLConfig,
    #[serde(default)]
    nss: NSSConfig,
}

impl FromStr for ConfigFile {
    type Err = anyhow::Error;

    fn from_str(file: &str) -> Result<Self, Self::Err> {
        let config = fs::read_to_string(file)?;
        Ok(toml::from_str(&config)?)
    }
}

impl Default for ConfigFile {
    fn default() -> ConfigFile {
        ConfigFile {
            openssl: Default::default(),
            nss: Default::default(),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "snuffy", about = "Sniff TLS data")]
struct Opts {
    #[structopt(short = "p", long = "pid")]
    pid: Option<i32>,
    #[structopt(short = "c", long = "command")]
    command: Option<String>,
    #[structopt(short = "d", long = "hex-dump")]
    hex_dump: bool,
    #[structopt(long = "libs", help="Which TLS libraries to attach to",
        possible_values = &TLS_LIBS)]
    libs: Vec<String>,
    #[structopt(long = "config", parse(try_from_str))]
    config: Option<ConfigFile>,
}

fn now() -> String {
    OffsetDateTime::now_local().format("[%T]")
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/snuffy/snuffy.elf"
    ))
}

struct ObservedState {
    fd_conns: HashMap<i32, SocketAddrV4>,
    dns: HashMap<String, Vec<Ipv4Addr>>,
    rev_dns: HashMap<Ipv4Addr, String>,
    ssl_hosts: HashMap<usize, String>,
    ssl_fds: HashMap<usize, i32>,
}

impl ObservedState {
    fn new() -> Self {
        ObservedState {
            fd_conns: HashMap::new(),
            dns: HashMap::new(),
            rev_dns: HashMap::new(),
            ssl_hosts: HashMap::new(),
            ssl_fds: HashMap::new(),
        }
    }

    fn record_connection(&mut self, fd: i32, address: SocketAddrV4) {
        self.fd_conns.insert(fd, address);
    }

    fn address_by_fd(&self, fd: &i32) -> Option<&SocketAddrV4> {
        self.fd_conns.get(fd)
    }

    fn record_dns(&mut self, host: String, ips: Vec<Ipv4Addr>) {
        for ip in &ips {
            self.rev_dns.insert(ip.clone(), host.clone());
        }
        self.dns.insert(host, ips);
    }

    fn lookup_name(&self, host: &str) -> Option<&Vec<Ipv4Addr>> {
        self.dns.get(host)
    }

    fn lookup_ip(&self, ip: &Ipv4Addr) -> Option<&str> {
        self.rev_dns.get(ip).map(|s| s.as_str())
    }

    fn record_ssl_host(&mut self, ssl_ctx: usize, host: String) {
        self.ssl_hosts.insert(ssl_ctx, host);
    }

    fn lookup_ssl_host(&self, ssl_ctx: &usize) -> Option<&str> {
        self.ssl_hosts.get(ssl_ctx).map(|s| s.as_str())
    }

    fn record_ssl_fd(&mut self, ssl_ctx: usize, fd: i32) {
        self.ssl_fds.insert(ssl_ctx, fd);
    }

    fn lookup_ssl_fd(&self, ssl_ctx: &usize) -> Option<&i32> {
        self.ssl_fds.get(ssl_ctx)
    }

    fn format_address(&self, addr: &SocketAddrV4) -> String {
        let host = self.lookup_ip(addr.ip());
        if let Some(host) = host {
            format!("{}:{} ({})", host, addr.port(), addr)
        } else {
            format!("{}", addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_connection() {
        let mut state = ObservedState::new();
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 1234;
        let addr = SocketAddrV4::new(ip, port);
        state.record_connection(1, addr.clone());

        assert_eq!(state.address_by_fd(&0), None);
        assert_eq!(state.address_by_fd(&1), Some(&addr));
    }

    #[test]
    fn test_record_dns() {
        let mut state = ObservedState::new();
        let host = "example.com".to_string();
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        state.record_dns(host, vec![ip]);

        assert_eq!(state.lookup_name("confused.ai"), None);
        assert_eq!(state.lookup_name("example.com"), Some(&vec![ip]));
        assert_eq!(state.lookup_ip(&Ipv4Addr::new(1, 1, 1, 1)), None);
        assert_eq!(
            state.lookup_ip(&Ipv4Addr::new(127, 0, 0, 1)),
            Some("example.com")
        );
    }

    #[test]
    fn test_record_ssl_host() {
        let mut state = ObservedState::new();
        let ctx_addr = 1234;
        let host = "example.com".to_string();
        state.record_ssl_host(ctx_addr, host);

        assert_eq!(state.lookup_ssl_host(&1111usize), None);
        assert_eq!(state.lookup_ssl_host(&ctx_addr), Some("example.com"));
    }

    #[test]
    fn test_record_ssl_fd() {
        let mut state = ObservedState::new();
        let ctx_addr = 1234;
        let fd = 0;
        state.record_ssl_fd(ctx_addr, fd);

        assert_eq!(state.lookup_ssl_fd(&1111usize), None);
        assert_eq!(state.lookup_ssl_fd(&ctx_addr), Some(&0));
    }
}
