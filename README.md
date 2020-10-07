# snuffy

Snuffy is a simple command line tool to inspect SSL/TLS connections. It currently supports [OpenSSL](https://openssl.org) and [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS).

For background info see the blog post https://confused.ai/posts/intercepting-zoom-tls-encryption-bpf-uprobes.

# Installation

In order to use snuffy you need to install the headers for the running kernel and LLVM 10.

To install them on ubuntu run:

```sh
sudo apt-get -y install build-essential zlib1g-dev \
        llvm-10-dev libclang-10-dev linux-headers-$(uname -r)
```

On fedora run:

```sh
yum install clang llvm llvm-devel zlib-devel kernel-devel
export LLVM_SYS_100_PREFIX=/usr
```

Finally install snuffy itself running:

```sh
cargo install --git https://github.com/alessandrod/snuffy snuffy
```

**NOTE**: if you installed rust in your home directory, the binary will be placed in `$HOME/.cargo/bin/snuffy`. If you use sudo to run snuffy, you'll have to use the full path.

# Usage

Snuffy uses the `bpf()` syscall, so you need to run it as root or a user with `CAP_SYS_ADMIN` privileges.

## With programs that link to OpenSSL or NSS dynamically

To instruments commands that link to OpenSSL or NSS dynamically, run:

```
# snuffy --hex-dump --command [COMMAND]
```

For example to instrument curl:

```
# snuffy --hex-dump --command /usr/bin/curl # then in another terminal run: curl --http1.1 https://www.google.com
[6:05:19] Connected to 127.0.0.53:53
[6:05:19] Resolved www.google.com to 216.58.199.68
[6:05:19] Connected to www.google.com:443 (216.58.199.68:443)
[6:05:19] Write 78 bytes to www.google.com:443 (216.58.199.68:443)
[6:05:19] |47455420 2f204854 54502f31 2e310d0a| GET / HTTP/1.1.. 00000000
[6:05:19] |486f7374 3a207777 772e676f 6f676c65| Host: www.google 00000010
[6:05:19] |2e636f6d 0d0a5573 65722d41 67656e74| .com..User-Agent 00000020
[6:05:19] |3a206375 726c2f37 2e36352e 330d0a41| : curl/7.65.3..A 00000030
[6:05:19] |63636570 743a202a 2f2a0d0a 0d0a|     ccept: */*....   00000040
[6:05:19]                                                        0000004e
[6:05:19] Read 1396 bytes from www.google.com:443 (216.58.199.68:443)
[6:05:19] |48545450 2f312e31 20323030 204f4b0d| HTTP/1.1 200 OK. 00000000
[6:05:19] |0a446174 653a2046 72692c20 30342053| .Date: Fri, 04 S 00000010
[6:05:19] |65702032 30323020 30363a32 303a3033| ep 2020 06:20:03 00000020
[6:05:19] |20474d54 0d0a4578 70697265 733a202d|  GMT..Expires: - 00000030
[6:05:19] |310d0a43 61636865 2d436f6e 74726f6c| 1..Cache-Control 00000040
[6:05:19] |3a207072 69766174 652c206d 61782d61| : private, max-a 00000050
```

If you omit the `--command` option, snuffy will intercept **all** the programs that use OpenSSL or NSS.

**NOTE**: Firefox links to NSS dynamically, but ships its own `libssl3.so` and `libnspr4.so`. To instrument firefox, you have to provide a config file pointing to those libraries, eg:

```toml
[nss]
libssl3="/usr/lib/firefox/libssl3.so"
libnspr4="/usr/lib/firefox/libnspr4.so"
```

## With programs that link to OpenSSL or NSS statically

If you want to instrument a program that links statically to OpenSSL or NSS and the symbols have been stripped, you need to provide a configuration file containing the `.text` section offsets of the TLS functions.

For example for OpenSSL put this in `config.toml`:

```toml
[openssl]
SSL_set_fd = 0xBADDCAFE
SSL_read = 0xBAAAAAAD
SSL_write = 0xDECAFBAD
```

And for NSS:

```toml
[nss]
SSL_SetURL = 0xBADDCAFE
PR_Recv = 0xBAAAAAAD
PR_Send = 0xDECAFBAD
```

(The offsets above are just examples, you need to provide working ones.)

Then run:

```
# snuffy --hex-dump --command COMMAND --config config.toml
```

For example assuming `zoom-config.toml` contains valid OpenSSL offsets for the zoom client:

```
# snuffy --hex-dump --command /opt/zoom/zoom --config zoom-config.toml # then start zoom
[4:56:18] Connected to 127.0.0.53:53
[4:56:18] Resolved us04web.zoom.us to 3.235.69.6
[4:56:18] Connected to us04web.zoom.us:443 (3.235.69.6:443)
[4:56:19] Write 571 bytes to us04web.zoom.us:443 (3.235.69.6:443)
[4:56:19] |504f5354 202f7265 6c656173 656e6f74| POST /releasenot 00000000
[4:56:19] |65732048 5454502f 312e310d 0a486f73| es HTTP/1.1..Hos 00000010
[4:56:19] |743a2075 73303477 65622e7a 6f6f6d2e| t: us04web.zoom. 00000020
[4:56:19] |75730d0a 55736572 2d416765 6e743a20| us..User-Agent:  00000030
[4:56:19] |4d6f7a69 6c6c612f 352e3020 285a4f4f| Mozilla/5.0 (ZOO 00000040
[4:56:19] |4d2e4c69 6e757820 5562756e 74752031| M.Linux Ubuntu 1 00000050
...

[4:56:19] Read 3088 bytes from us04web.zoom.us:443 (3.235.69.6:443)
[4:56:19] |48545450 2f312e31 20323030 200d0a44| HTTP/1.1 200 ..D 00000000
[4:56:19] |6174653a 20467269 2c203034 20536570| ate: Fri, 04 Sep 00000010
[4:56:19] |20323032 30203035 3a31313a 30352047|  2020 05:11:05 G 00000020
[4:56:19] |4d540d0a 436f6e74 656e742d 54797065| MT..Content-Type 00000030
[4:56:19] |3a206170 706c6963 6174696f 6e2f782d| : application/x- 00000040
[4:56:19] |70726f74 6f627566 3b636861 72736574| protobuf;charset 00000050
...
```
