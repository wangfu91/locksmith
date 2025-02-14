use anyhow::Context;
use clap::Parser;
use std::collections::HashSet;
use std::time::Instant;

use log::LevelFilter;
use log::{error, info, warn};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

mod handle_ext;
mod nt_ext;
mod path_ext;
mod process_ext;
mod safe_handle;
mod to_string;

#[derive(Parser, Debug)]
#[command(name = "locksmith")]
#[command(about = "locksmith", long_about = None)]
struct Cli {
    path: String,
}

fn main() {
    init_logger(LevelFilter::Info).unwrap_or_else(|err| {
        eprintln!("init_logger failed, err: {:?}", err);
    });
    let start = Instant::now();
    let cli = Cli::parse();
    let find_result = find_locker(&cli.path);
    let elapsed = start.elapsed();

    match find_result {
        Ok(results) => {
            if results.is_empty() {
                warn!("No locker found");
            } else {
                for result in results {
                    info!("pid: {}", result.pid);
                    info!("name: {}", result.name);
                    info!("user: {}", result.user);
                    info!("path: {}\n", result.process_full_path);
                }
            }
        }
        Err(err) => {
            error!("find_locker failed, err: {:?}", err);
        }
    }

    info!("elapsed: {:.2}s", elapsed.as_secs_f64());
}

fn find_locker(path: &str) -> anyhow::Result<HashSet<ProcessResult>> {
    let nt_path = path_ext::win32_path_to_nt_path(path.to_string())
        .with_context(|| "win32_path_to_nt_path failed")?;

    let mut process_results = HashSet::<ProcessResult>::new();

    let handle_infos = handle_ext::enum_handles().with_context(|| "enum_handles failed")?;

    for handle_info in handle_infos {
        if handle_info.nt_path == nt_path {
            let pid = handle_info.pid;
            let name =
                process_ext::pid_to_process_name(pid).unwrap_or_else(|_| "unknown".to_string());

            let user = if let Ok((domain, user)) = process_ext::pid_to_user(pid) {
                format!("{}\\{}", domain, user)
            } else {
                "unknown".to_string()
            };
            let process_full_path = process_ext::pid_to_process_full_path(pid)
                .unwrap_or_else(|_| "unknown".to_string());
            let process_result = ProcessResult {
                pid: handle_info.pid,
                name,
                user,
                process_full_path,
            };
            process_results.insert(process_result);
        }
    }

    let proces_infos = process_ext::enum_processes().with_context(|| "enum_processes failed")?;
    for process_info in proces_infos {
        for module in process_info.modules {
            if module == nt_path {
                let process_result = ProcessResult {
                    pid: process_info.pid,
                    name: process_info.process_name.clone(),
                    user: process_info.user.clone(),
                    process_full_path: process_info.process_full_path.clone(),
                };
                process_results.insert(process_result);
            }
        }
    }

    Ok(process_results)
}

#[derive(Hash, Eq, PartialEq, Debug)]
struct ProcessResult {
    pid: u32,
    name: String,
    user: String,
    process_full_path: String,
}

fn init_logger(level: LevelFilter) -> anyhow::Result<()> {
    // Create a console appender
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
        .build();

    // Configure the logger to write to the console appender
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(level))?;

    // Initialize the logger
    log4rs::init_config(config)?;

    Ok(())
}
