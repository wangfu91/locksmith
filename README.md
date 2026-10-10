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

Inaccessible or exited processes are silently skipped during scanning, including when running as administrator. Results list the owners Locksmith could identify.

Exit codes: `0` scan completed, `1` operation failed, `2` an entire scan method was unavailable or arguments were invalid.

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

## 📜 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Attribution

This project is a Rust port of the PowerToys's FileLockSmith module.
The original implementation is in C++ and can be found here: https://github.com/microsoft/PowerToys/tree/main/src/modules/FileLocksmith.
