use anyhow::Context;
use clap::Parser;
use std::collections::HashMap;
use std::time::Instant;

mod handle_ext;
mod nt_ext;
mod path_ext;
mod process_ext;
mod safe_handle;
mod string_ext;

#[derive(Parser, Debug)]
#[command(name = "locksmith")]
#[command(author = "Fu Wang <wangfu91@hotmail.com>")]
#[command(
    about = "locksmith - Find processes locking your files",
    long_about = "A Windows utility to find out which processes are using your files"
)]
struct Cli {
    /// Path to the file you want to check for locks
    #[arg(required = true)]
    path: String,

    /// Show detailed information about the process
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let start = Instant::now();
    let cli = Cli::parse();
    let find_result = find_locker(&cli);
    let elapsed = start.elapsed();

    match find_result {
        Ok(results) => {
            if results.is_empty() {
                eprintln!("No locker found");
            } else {
                println!("Found {} locker(s):\n", results.len());
                for (_, result) in results {
                    println!("pid: {}", result.pid);
                    println!("name: {}", result.name);
                    println!("path: {}", result.path);
                    if cli.verbose {
                        println!("modules: {:#?}", result.modules);
                    }
                    println!();
                }
            }
        }
        Err(err) => {
            eprintln!("find_locker failed, err: {:?}", err);
        }
    }

    println!("elapsed: {:.2}s", elapsed.as_secs_f64());
}

fn find_locker(cli: &Cli) -> anyhow::Result<HashMap<u32, ProcessResult>> {
    let nt_path = path_ext::win32_path_to_nt_path(cli.path.to_string())
        .with_context(|| "win32_path_to_nt_path failed")?;

    let mut process_results = HashMap::<u32, ProcessResult>::new();

    let handle_infos = handle_ext::enum_handles().with_context(|| "enum_handles failed")?;

    for handle_info in handle_infos {
        if handle_info.nt_path == nt_path {
            let pid = handle_info.pid;
            let name =
                process_ext::pid_to_process_name(pid).unwrap_or_else(|_| "unknown".to_string());
            let path = process_ext::pid_to_process_full_path(pid)
                .unwrap_or_else(|_| "unknown".to_string());
            let modules = if cli.verbose {
                process_ext::enum_process_modules(pid).unwrap_or_else(|_| Vec::new())
            } else {
                Vec::new()
            };
            let process_result = ProcessResult {
                pid,
                name,
                path,
                modules,
            };
            process_results.insert(pid, process_result);
        }
    }

    let proces_infos = process_ext::enum_processes().with_context(|| "enum_processes failed")?;
    for process_info in proces_infos {
        for module in &process_info.modules {
            if module == &nt_path {
                let process_result = ProcessResult {
                    pid: process_info.pid,
                    name: process_info.process_name.clone(),
                    path: process_info.process_full_path.clone(),
                    modules: if cli.verbose {
                        process_info.modules.clone()
                    } else {
                        Vec::new()
                    },
                };
                process_results.insert(process_info.pid, process_result);
            }
        }
    }

    Ok(process_results)
}

#[derive(Debug)]
struct ProcessResult {
    pid: u32,
    name: String,
    path: String,
    modules: Vec<String>,
}
