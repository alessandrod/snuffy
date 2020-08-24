use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cargo_bpf_lib::bindgen as bpf_bindgen;

fn main() {
    if env::var("CARGO_FEATURE_PROBES").is_err() {
        return;
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    gen_bindings(
        &out_dir,
        "include/user_bindings.h",
        "gen_user_bindings",
        &["addrinfo"],
    );
}

fn gen_bindings(out_dir: &Path, header: &str, name: &str, types: &[&str]) {
    let mut builder = bpf_bindgen::builder().header(header);
    for ty in types {
        builder = builder.whitelist_type(*ty);
    }

    let mut bindings = builder
        .generate()
        .expect("failed to generate bindings")
        .to_string();
    let accessors = bpf_bindgen::generate_read_accessors(&bindings, types);
    bindings.push_str("use redbpf_probes::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    create_module(out_dir.join(name).with_extension("rs"), name, &bindings).unwrap();
}

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}
