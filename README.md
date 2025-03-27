# Locksmith 🔒

A Windows utility to find out which processes are locking your files.

Ever wondered why you can't delete or modify a file? Locksmith will help you identify the processes that are holding onto your files.

## Features

- Find processes that have open handles to a specific file
- Find processes that have loaded a specific DLL/module
- Fast and lightweight command-line interface

## Installation

```bash
cargo install win-locksmith
```

## Usage

Basic usage:
```bash
locksmith <file_path>
```

### Examples

Finding processes locking a file:
```bash
> locksmith "C:\Users\username\Desktop\important.txt"
Found 2 locker(s):

pid: 1234
name: notepad.exe
path: C:\Windows\System32\notepad.exe

pid: 5678
name: explorer.exe
path: C:\Windows\explorer.exe
```

## Building from Source
On Windows:
```bash
git clone https://github.com/wangfu91/locksmith
cd locksmith
cargo build --release
```

## License

 * MIT license

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Attribution

This project is a Rust port of the PowerToys's FileLockSmith module.
The original implementation is in C++ and can be found here: https://github.com/microsoft/PowerToys/tree/main/src/modules/FileLocksmith.
