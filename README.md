# Locksmith 🔒 [![Crates.io](https://img.shields.io/crates/v/win-locksmith.svg)](https://crates.io/crates/win-locksmith) [![Downloads](https://img.shields.io/crates/d/win-locksmith.svg)](https://crates.io/crates/win-locksmith) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Windows command-line utility that identifies processes using a file or directory, helping you investigate why it cannot be deleted or modified.

## ✨ Features

- Find processes that have open handles to a specific file
- Find processes that have loaded a specific DLL/module
- Scan a directory and files below it
- Fast and lightweight command-line interface

## 📦 Installation

Locksmith runs on Windows. Install it from the Microsoft Store:

<a href="https://apps.microsoft.com/detail/9PF14DG43JH0">
  <img src="https://get.microsoft.com/images/en-us%20dark.svg" alt="Get it from Microsoft Store" width="200" />
</a>

Or install with Cargo, which requires [Rust and Cargo](https://www.rust-lang.org/tools/install):

```sh
cargo install win-locksmith
```

## 🚀 Usage

```text
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

Processes that cannot be accessed or have already exited are silently skipped, even when running as administrator. Results include only the processes Locksmith could identify; an empty result does not guarantee that the path is unused.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed. |
| `1` | Operation failed. |
| `2` | An entire scan method was unavailable, or arguments were invalid. |

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

Scanning a directory and the files below it:

```powershell
locksmith "C:\Users\username\Desktop\my-folder"
```

Forcefully terminating processes locking a file (requires confirmation):

```powershell
locksmith --kill "C:\Users\username\Desktop\important.txt"
```

**Warning:** Forcefully terminating processes can cause unsaved work to be lost.

## 🛠️ Building from Source

On Windows:

```sh
git clone https://github.com/wangfu91/locksmith
cd locksmith
cargo build --release
```

For Microsoft Store MSIX packaging, see [the packaging guide](packaging/msix/README.md).

## 📜 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Attribution

This project is a Rust port of the [File Locksmith module in Microsoft PowerToys](https://github.com/microsoft/PowerToys/tree/main/src/modules/FileLocksmith), originally implemented in C++.
