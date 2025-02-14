# Locksmith 🔒

A Windows utility to find out which processes are locking your files. 

Ever wondered why you can't delete or modify a file? Locksmith will help you identify the processes that are holding onto your files.

## Features

- Find processes that have open handles to a specific file
- Find processes that have loaded a specific DLL/module
- Detailed process information with verbose mode
- Fast and lightweight command-line interface

## Installation

```bash
cargo install locksmith
```

## Usage

Basic usage:
```bash
locksmith <file_path>
```

Show detailed process information:
```bash
locksmith --verbose <file_path>
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

With verbose mode:
```bash
> locksmith -v "C:\Program Files\App\lib.dll"
Found 1 locker(s):

pid: 9876
name: app.exe
path: C:\Program Files\App\app.exe
modules: [
    "C:\\Program Files\\App\\lib.dll",
    "C:\\Windows\\System32\\kernel32.dll",
    // ... more modules ...
]
```

## Building from Source
On Windows:
```bash
git clone https://github.com/wangfu91/locksmith
cd locksmith
cargo build --release
```

## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
