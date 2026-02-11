# Rust Nanodump

Rust rewrite of [**nanodump**](https://github.com/fortra/nanodump), a low-level LSASS memory dumping tool for Windows. Designed for research, red team tooling, and learning purposes.

## Features

- Dump LSASS memory directly using syscalls
- Handle enumeration and process inspection
- Minimal WinAPI usage for stealth and performance
- Modular Rust architecture for easier maintenance

## Build Requirements

- Rust 1.88+ (for latest features)
- Optional: `cargo-expand` for macro expansion debugging

## Usage

```bash
cargo build --release
.\target\release\rust-nanodump.exe
```

Building on linux : 
```bash
cargo build --release --target x86_64-pc-windows-gnu
```