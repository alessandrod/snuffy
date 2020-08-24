// Copyright 2020 Alessandro Decina
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use anyhow::anyhow;
use futures::stream::StreamExt;
use getopts::Options;
use hexdump::hexdump_iter;
use redbpf::{load::Loader, HashMap as BPFHashMap};
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::raw::c_char;
use std::{cmp, fs, path::Path, ptr};
use time::OffsetDateTime;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

use probes::snuffy::{AccessMode, Config, Connection, SSLBuffer, COMM_LEN, CONFIG_KEY, DNS};

fn main() -> Result<(), anyhow::Error> {
    let opts = match parse_opts()? {
        Some(opts) => opts,
        None => return Ok(()),
    };

    let mut runtime = Runtime::new()?;
    let _ = runtime.block_on(async {
        let mut loader = Loader::load(probe_code()).expect("error loading probe");

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
                extract_fds: opts.trace_conns as usize,
            },
        );

        // attach the uprobes
        for uprobe in loader.uprobes_mut() {
            match uprobe.name().as_str() {
                "getaddrinfo" | "getaddrinfo_ret" => {
                    uprobe
                        .attach_uprobe(Some("getaddrinfo"), 0, "libc", opts.pid)
                        .expect(&format!("error attaching program getaddrinfo"));
                }
                n @ "connect" => {
                    uprobe
                        .attach_uprobe(Some(n), 0, "libpthread", opts.pid)
                        .expect(&format!("error attaching program {}", n));
                }
                "SSL_read" | "SSL_read_ret" => {
                    let (fn_name, offset, target) = match &opts.ssl_offsets {
                        Some(off) => (None, off.read, opts.command.as_ref().unwrap().as_str()),
                        None => (Some("SSL_read"), 0, "libssl"),
                    };
                    uprobe
                        .attach_uprobe(fn_name, offset, target, opts.pid)
                        .expect(&format!("error attaching to SSL_read"));
                }
                "SSL_write" => {
                    let (fn_name, offset, target) = match &opts.ssl_offsets {
                        Some(off) => (None, off.write, opts.command.as_ref().unwrap().as_str()),
                        None => (Some("SSL_write"), 0, "libssl"),
                    };
                    uprobe
                        .attach_uprobe(fn_name, offset, &target, opts.pid)
                        .expect(&format!("error attaching to SSL_write"));
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
        signal::ctrl_c().await
    });

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

#[derive(Debug)]
struct SSLOffsets {
    read: u64,
    write: u64,
}

#[derive(Debug)]
struct Opts {
    pid: Option<i32>,
    trace_conns: bool,
    command: Option<String>,
    hex_dump: bool,
    ssl_offsets: Option<SSLOffsets>,
}

fn parse_opts() -> Result<Option<Opts>, anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("p", "PID", "the PID of the program to attach to", "PID");
    opts.optflag(
        "t",
        "trace-connections",
        "attempt to associate reads and writes to TCP connections",
    );
    opts.optflag("d", "hex-dump", "print an hex dump of the network data");
    opts.optopt(
        "c",
        "command",
        "the path to command to attach to. Required when providing custom offsets.",
        "COMMAND",
    );
    opts.optopt(
        "o",
        "offsets",
        "toml file including ssl_read and ssl_write keys with custom offsets.",
        "offsets.toml",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("{}\n", f);
            print_usage(&program, opts);
            return Ok(None);
        }
    };

    if matches.opt_present("h") || !matches.free.is_empty() {
        print_usage(&program, opts);
        return Ok(None);
    }

    if matches.opt_present("o") && !matches.opt_present("c") {
        eprintln!("The option 'command' is required when providing custom offsets\n");
        print_usage(&program, opts);
        return Ok(None);
    }

    let ssl_offsets = match matches.opt_str("o") {
        Some(file) => {
            let config = fs::read_to_string(&file).map(|s| s.parse::<toml::Value>())??;
            Some(SSLOffsets {
                read: offset_value(&config, "ssl_read")?,
                write: offset_value(&config, "ssl_write")?,
            })
        }
        None => None,
    };

    let command = matches.opt_str("c");
    let pid = matches.opt_str("p").map(|p| p.parse::<i32>().unwrap());
    let trace_conns = matches.opt_present("t");
    let hex_dump = matches.opt_present("d");
    Ok(Some(Opts {
        command,
        pid,
        trace_conns,
        hex_dump,
        ssl_offsets,
    }))
}

fn offset_value(config: &toml::Value, key: &str) -> Result<u64, anyhow::Error> {
    let offset = config
        .get(key)
        .ok_or_else(|| anyhow!("missing {} offset", key))?
        .as_integer()
        .ok_or_else(|| anyhow!("invalid {} offset", key));
    offset.map(|o| o as u64)
}

fn now() -> String {
    OffsetDateTime::now().format("[%T]")
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] [offsets.toml]", program);
    print!("{}", opts.usage(&brief));
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/snuffy/snuffy.elf"
    ))
}
