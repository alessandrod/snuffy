// Copyright 2020 Alessandro Decina
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::raw::c_char;
use std::str::FromStr;
use std::{cmp, fs, path::Path, ptr};

use anyhow::{anyhow, Context};
use futures::stream::StreamExt;
use hexdump::hexdump_iter;
use redbpf::{load::Loader, HashMap as BPFHashMap, UProbe};
use serde::Deserialize;
use structopt::StructOpt;
use time::OffsetDateTime;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

use snuffy_probes::snuffy::{AccessMode, Config, Connection, SSLBuffer, COMM_LEN, CONFIG_KEY, DNS};

fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::from_args();

    let mut runtime = Runtime::new()?;
    let _ = runtime.block_on(async {
        let mut loader =
            Loader::load(probe_code()).map_err(|e| anyhow!("Error loading probes: {:?}", e))?;
        let config = BPFHashMap::<usize, Config>::new(loader.map("config").unwrap()).unwrap();
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

        config.set(
            CONFIG_KEY,
            Config {
                target_comm_set: target_comm_set as usize,
                target_comm,
                extract_fds: opts.trace_connections as usize,
            },
        );

        // attach the uprobes
        for uprobe in loader.uprobes_mut() {
            match uprobe.name().as_str() {
                "getaddrinfo" | "getaddrinfo_ret" => attach_uprobe(
                    uprobe,
                    "getaddrinfo",
                    Some("getaddrinfo"),
                    0,
                    "libc",
                    opts.pid,
                )?,
                n @ "connect" => {
                    attach_uprobe(uprobe, "connect", Some(n), 0, "libpthread", opts.pid)?
                }
                "SSL_read" | "SSL_read_ret" => {
                    let (fn_name, offset, target) = match &opts.offsets {
                        Some(off) => (None, off.ssl_read, opts.command.as_ref().unwrap().as_str()),
                        None => (Some("SSL_read"), 0, "libssl"),
                    };
                    attach_uprobe(uprobe, "SSL_read", fn_name, offset, target, opts.pid)?
                }
                "SSL_write" => {
                    let (fn_name, offset, target) = match &opts.offsets {
                        Some(off) => (None, off.ssl_write, opts.command.as_ref().unwrap().as_str()),
                        None => (Some("SSL_write"), 0, "libssl"),
                    };
                    attach_uprobe(uprobe, "SSL_write", fn_name, offset, &target, opts.pid)?
                }
                _ => continue,
            }
        }

        let mut connections: HashMap<i32, SocketAddrV4> = HashMap::new();
        let mut hosts = Hosts::new();
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
                            hosts.insert(ip, host.to_string());
                            println!("{} Resolved {} to {}", now(), host, ip);
                        }
                        "connection" => {
                            let conn = unsafe { ptr::read(event.as_ptr() as *const Connection) };
                            let ip = Ipv4Addr::from(unsafe {
                                mem::transmute::<u32, [u8; 4]>(conn.addr)
                            });
                            let addr = SocketAddrV4::new(ip, conn.port as u16);
                            println!("{} Connected to {}", now(), hosts.format(&addr));
                            connections.insert(conn.fd as i32, addr);
                        }
                        "ssl_buffer" => {
                            let buf = unsafe { ptr::read(event.as_ptr() as *const SSLBuffer) };
                            if let Some(data) = buffers.push(&buf) {
                                let complete = if buf.len == data.len() {
                                    ""
                                } else {
                                    " (incomplete)"
                                };
                                let addr = connections.get(&buf.fd);
                                if buf.mode == AccessMode::Read {
                                    println!(
                                        "{} Read {} bytes{} {}",
                                        now(),
                                        data.len(),
                                        complete,
                                        addr.map(|addr| format!("from {}", hosts.format(addr)))
                                            .unwrap_or("".to_string())
                                    );
                                } else {
                                    println!(
                                        "{} Write {} bytes{} {}",
                                        now(),
                                        data.len(),
                                        complete,
                                        addr.map(|addr| format!("to {}", hosts.format(addr)))
                                            .unwrap_or("".to_string())
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
            .entry((ssl_buf.ssl_handle, ssl_buf.mode))
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

struct Hosts {
    hosts: HashMap<Ipv4Addr, String>,
}

impl Hosts {
    fn new() -> Self {
        Self {
            hosts: HashMap::new(),
        }
    }

    fn insert(&mut self, ip: Ipv4Addr, host: String) {
        self.hosts.insert(ip, host);
    }

    fn format(&self, addr: &SocketAddrV4) -> String {
        let host = self.hosts.get(addr.ip());
        if let Some(host) = host {
            format!("{}:{} ({})", host, addr.port(), addr)
        } else {
            format!("{}", addr)
        }
    }
}

#[derive(Debug, Deserialize)]
struct Offsets {
    ssl_read: u64,
    ssl_write: u64,
}

impl FromStr for Offsets {
    type Err = anyhow::Error;

    fn from_str(file: &str) -> Result<Self, Self::Err> {
        let config = fs::read_to_string(file)?;
        Ok(toml::from_str(&config)?)
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "snuffy", about = "Sniff TLS data")]
struct Opts {
    #[structopt(short = "p", long = "pid")]
    pid: Option<i32>,
    #[structopt(short = "t", long = "trace-connections")]
    trace_connections: bool,
    #[structopt(short = "c", long = "command")]
    command: Option<String>,
    #[structopt(short = "d", long = "hex-dump")]
    hex_dump: bool,
    #[structopt(
        short = "o",
        long = "offsets",
        requires = "command",
        parse(try_from_str)
    )]
    offsets: Option<Offsets>,
}

fn attach_uprobe(
    uprobe: &mut UProbe,
    name: &str,
    fn_name: Option<&str>,
    offset: u64,
    target: &str,
    pid: Option<i32>,
) -> Result<(), anyhow::Error> {
    uprobe
        .attach_uprobe(fn_name, offset, target, pid)
        .map_err(|e| anyhow!("error attaching to `{}`: {:?}", name, e))
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
