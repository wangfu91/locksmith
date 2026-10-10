# Locksmith 🔒 [![Crates.io](https://img.shields.io/crates/v/win-locksmith.svg)](https://crates.io/crates/win-locksmith) [![Downloads](https://img.shields.io/crates/d/win-locksmith.svg)](https://crates.io/crates/win-locksmith) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Windows utility to find out which processes are locking your files.

Ever wondered why you can't delete or modify a file? Locksmith will help you identify the processes that are holding onto your files.

## ✨ Features

- Find processes that have open handles to a specific file
- Find processes that have loaded a specific DLL/module
- Scan a directory and files below it
- Fast and lightweight command-line interface

## 📦 Installation

```sh
cargo install win-locksmith
```

## 🚀 Usage

```sh
Usage: locksmith.exe [OPTIONS] <PATH>

Arguments:
  <PATH>
          File or directory to check for processes using it

Options:
  -k, --kill
          Forcefully kill the processes locking the file (requires confirmation)

  -h, --help
          Print help (see a summary with '-h')
```

### Results and exit status

Files match a complete native path; directories also match descendant paths at
directory boundaries. Path data stays in native Windows UTF-16 throughout the
scan. Names are compared using Windows
[ordinal Unicode case-insensitive rules](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-comparestringordinal).
An open disk handle or a loaded module shows that a process uses the target;
the handle's sharing mode may still allow deletion or modification.

Each matching process is displayed once. Unavailable display metadata appears
as `unknown`; the match is retained. Failed queries produce a warning with a
failure count and up to eight examples. No matches in an incomplete scan does
not establish that the target is unused.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed within the supported scope, including no matches; help also succeeds. |
| `1` | Operational failure, such as an invalid target, confirmation I/O failure, or failed termination. |
| `2` | Scan results may be incomplete; also used by the argument parser for invalid usage. |

`--kill` requires an explicit `y` confirmation; any other response cancels.
The original process handles remain open from discovery through confirmation.
Termination never reopens a process by its PID. If termination access was
unavailable during discovery, that process remains in the results and its
termination attempt reports failure.

Module scanning queries existing memory mappings instead of reopening module
filenames supplied by other processes. The user-selected target is still opened
normally, including when it is on a network share.

### Scan limits

The scan is a snapshot: processes can exit and modules or handles can change.
Protected processes, insufficient rights and architecture restrictions can
prevent queries, and are reported as incomplete results. Matching does not
implement per-directory case-sensitive NTFS settings, hard-link identity or
directory ancestry through junction aliases.

System queries have capacity and retry limits. Individual filesystem queries
remain synchronous, so an unresponsive filesystem driver or remote provider
can delay a scan. No forced-thread-termination recovery is used.

### 📝 Examples

Finding processes locking a file:
```powershell
> locksmith "C:\Users\username\Desktop\important.txt"
Found 2 locker(s):

pid: 1234
name: notepad.exe
path: C:\Windows\System32\notepad.exe

pid: 5678
name: explorer.exe
path: C:\Windows\explorer.exe
```

## 🛠️ Building from Source
On Windows:
```sh
git clone https://github.com/wangfu91/locksmith
cd locksmith
cargo build --release
```

Local verification and Windows CI use:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
```

Tests include deterministic error and boundary cases, real native/long file
paths, a trusted local DLL loaded from a long path, and termination of a test's
own child process. Windows system-handle tests require normal process-query
access; restrictive execution sandboxes may deny the system snapshot API.

## 📜 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Attribution

This project is a Rust port of the PowerToys's FileLockSmith module.
The original implementation is in C++ and can be found here: https://github.com/microsoft/PowerToys/tree/main/src/modules/FileLocksmith.
