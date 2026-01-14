# serenelib

Core userspace library for Serene.

## Overview

A `no_std` Rust library providing essential functionality for userspace programs running on Serene.

## Features

- **System calls**: Wrappers for kernel system calls (IPC, process management, capabilities)
- **Debug writer**: Print macros and debug output functionality
- **IPC utilities**: Inter-process communication helpers

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
serenelib = { git = "https://github.com/serenekernel/serenelib.git" }
```

Import in your code:
```rust
use serenelib::{print, println};
use serenelib::syscalls::*;
```
