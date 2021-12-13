# clean-dns

this is a fork version of [clean-dns-bpf](https://github.com/ihciah/clean-dns-bpf), please refer to it for details, but use [aya](https://github.com/aya-rs/aya) instead and contains a userspace program.
## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
