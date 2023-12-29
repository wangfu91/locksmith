use anyhow::Context;
use clap::{Parser, Subcommand};

mod handle_ext;
mod path_ext;
mod process_ext;
mod safe_handle;
mod to_string;

#[derive(Parser, Debug)]
#[command(name = "locksmith")]
#[command(about = "locksmith", long_about = None)]
struct Cli {
    path: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {}

fn main() {
    //let cli = Cli::parse();

    let path = r"C:\Users\WangF\Desktop\Welcome to Word.docx";

    let find_result = find_locker(path);

    match find_result {
        Ok(results) => {
            if results.is_empty() {
                println!("no locker found");
            } else {
                for result in results {
                    println!("pid: {}", result.pid);
                    println!("process_name: {}", result.process_name);
                    println!("process_full_path: {}", result.process_full_path);
                    println!();
                }
            }
        }
        Err(err) => {
            println!("find_locker failed, err: {:?}", err);
        }
    }
}

fn find_locker(path: &str) -> anyhow::Result<Vec<ProcessResult>> {
    let nt_path = path_ext::win32_path_to_nt_path(path.to_string())
        .with_context(|| "win32_path_to_nt_path failed")?;

    let mut process_result_collection = Vec::<ProcessResult>::new();

    let handle_infos = handle_ext::enum_handles().with_context(|| "enum_handles failed")?;

    for handle_info in handle_infos {
        if handle_info.nt_path == nt_path {
            let process_result = ProcessResult {
                pid: handle_info.pid,
                process_name: process_ext::pid_to_process_name(handle_info.pid)
                    .unwrap_or_else(|_| "unknown".to_string()),
                process_full_path: process_ext::pid_to_process_full_path(handle_info.pid)
                    .unwrap_or_else(|_| "unknown".to_string()),
            };
            process_result_collection.push(process_result);
        }
    }

    let proces_infos = process_ext::enum_processes().with_context(|| "enum_processes failed")?;
    for process_info in proces_infos {
        for module in process_info.modules {
            if module == nt_path {
                let process_result = ProcessResult {
                    pid: process_info.pid,
                    process_name: process_info.process_name.clone(),
                    process_full_path: process_info.process_full_path.clone(),
                };
                process_result_collection.push(process_result);
            }
        }
    }

    Ok(process_result_collection)
}

struct ProcessResult {
    pid: u32,
    process_name: String,
    process_full_path: String,
}
