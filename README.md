<p align="center">
  <img src="./.github/banner.png" alt="Nanorust banner">
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/Hakumarachi/Nanorust" alt="Latest release">
  <a href="https://twitter.com/intent/follow?screen_name=Akumarachi">
    <img src="https://img.shields.io/twitter/follow/Akumarachi?label=Akumarachi&style=social" alt="Twitter Follow">
  </a>
</p>

---
<p align="center">
Rust rewrite of <b><a href="https://github.com/fortra/nanodump">nanodump</a></b>, a low-level LSASS memory dumping tool for Windows. Built for research, red team tooling, and educational purposes.
</p>

## Usage

```bash
Usage: nanorust.exe [OPTIONS]

Options:
      --lsass-pid <LSASS_PID>  lsass pid
      --get-pid-and-leave      Only print lsass pid value
  -v, --verbose...             Increase verbosity (-v, -vv, -vvv)
  -q, --quiet                  Quiet mode (no output)
  -w, --write-dump-to-disk     Write dump to disk
  -p, --path <PATH>            Dump path [default: dump.bin]
  -h, --help                   Print help
  -V, --version                Print version
```

## Features

### Hell's / Tartarus gate
**Hell’s Gate** and **Tartarus Gate** are direct syscall techniques used to bypass userland API hooking.

Instead of calling Windows API functions like `NtOpenProcess` through ntdll exports, 
these methods dynamically resolve and invoke system calls directly by extracting syscall numbers from ntdll at runtime and syscall address within the ntdll. 

This helps evade EDR hooks placed on high-level API stubs and provides lower-level, 
more controlled interaction with the Windows kernel.

### Handle duplication
As opening a handle to LSASS can be detected, nanorust can instead search for existing handles to LSASS.
If one is found, it will copy it and use it to create the minidump.
Note that it is not guaranteed to find such a handle.

## Build Requirements

- Rust 1.88+ (for latest features)
- Optional: `cargo-expand` for macro expansion debugging

## Build

> **For now, nanorust is only available for x64 target system**

```bash
cargo build --release
```