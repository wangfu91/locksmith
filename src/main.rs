use anyhow::Context;
use clap::Parser;
use colored::*; // Added for colored output
use std::collections::HashMap;
use std::io::{self, Write}; // Added for user input and stdout flush
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

    /// Forcefully kill the processes locking the file (requires confirmation)
    #[arg(short, long, default_value_t = false)]
    force: bool,
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
                for result in results.values() {
                    // Borrow results for printing
                    println!("pid: {}", result.pid);
                    println!("name: {}", result.name);
                    println!("path: {}", result.path);
                    println!();
                }

                // Add logic for --force flag
                if cli.force {
                    println!(
                        "{}",
                        "WARNING: You are about to attempt to KILL the process(es) listed above."
                            .bold()
                            .yellow()
                    );
                    println!(
                        "{}",
                        "This is a DESTRUCTIVE and UNRECOVERABLE operation that could lead to data loss or system instability."
                            .bold()
                            .red()
                    );
                    print!(
                        "{} ",
                        "Are you absolutely sure you want to proceed? (y/N):"
                            .bold()
                            .yellow()
                    );
                    io::stdout()
                        .flush()
                        .context("Failed to flush stdout")
                        .unwrap_or_else(|e| eprintln!("Error flushing stdout: {}", e));

                    let mut confirmation = String::new();
                    match io::stdin().read_line(&mut confirmation) {
                        Ok(_) => {
                            if confirmation.trim().eq_ignore_ascii_case("y") {
                                println!("Proceeding to kill processes...");
                                match kill_processes(&results) {
                                    Ok(killed_count) => {
                                        if killed_count > 0 {
                                            println!(
                                                "Successfully attempted to kill {} process(es).",
                                                killed_count
                                            );
                                        } else {
                                            println!("No processes were targeted or killed.");
                                        }
                                        if killed_count < results.len() {
                                            println!(
                                                "{}",
                                                "Note: Some processes might not have been killed due to errors, lack of permissions, or if they already exited."
                                                .yellow()
                                            );
                                        }
                                    }
                                    Err(e) => eprintln!(
                                        "An error occurred during the kill process: {:?}",
                                        e
                                    ),
                                }
                            } else {
                                println!("Operation cancelled by user.");
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read user input: {:?}. Operation cancelled.", e);
                        }
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("find_locker failed, err: {:?}", err);
        }
    }

    println!("elapsed: {:.2}s", elapsed.as_secs_f64());
}

// Add the kill_processes function
fn kill_processes(processes: &HashMap<u32, ProcessResult>) -> anyhow::Result<usize> {
    let mut killed_count = 0;
    if processes.is_empty() {
        println!("No processes to kill.");
        return Ok(0);
    }

    println!(
        "{}",
        "IMPORTANT: Attempting to terminate processes. This can have unintended consequences."
            .bold()
            .red()
    );

    for (pid, process_info) in processes {
        println!(
            "Attempting to kill process: PID {}, Name: '{}', Path: '{}'",
            process_info.pid, process_info.name, process_info.path
        );
        match process_ext::kill_process_by_pid(*pid) {
            // Calling the function from process_ext module
            Ok(_) => {
                println!(
                    "Successfully sent termination signal to process PID {}.",
                    pid
                );
                killed_count += 1;
            }
            Err(e) => {
                eprintln!("Failed to kill process PID {}: {:?}", pid, e);
                // Decide if you want to stop on error or continue
            }
        }
    }
    Ok(killed_count)
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
            let process_result = ProcessResult { pid, name, path };
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
}
