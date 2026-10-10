use anyhow::Context;
use clap::Parser;
use colored::Colorize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

mod diagnostics;
mod handle_ext;
mod nt_ext;
mod path_ext;
mod process_ext;
mod string_ext;
mod wide_query;

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
    path: PathBuf,

    /// Forcefully kill the processes locking the file (requires confirmation)
    #[arg(short = 'k', long, default_value_t = false)]
    kill: bool,
}

fn main() -> std::process::ExitCode {
    match run(&Cli::parse()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<std::process::ExitCode> {
    let start = Instant::now();
    let scan = find_locker(cli)?;
    let partial = scan.diagnostics.failed_operations > 0;
    if partial {
        eprintln!(
            "Warning: {} query operation(s) failed; scan results may be incomplete.",
            scan.diagnostics.failed_operations
        );
        for example in &scan.diagnostics.examples {
            eprintln!("  {example}");
        }
    }
    if scan.processes.is_empty() {
        eprintln!(
            "No locker found{}",
            if partial {
                " in the accessible results"
            } else {
                ""
            }
        );
    } else {
        println!(
            "Found {} locker(s) in {:.2}s:\n",
            scan.processes.len(),
            start.elapsed().as_secs_f64()
        );
        let mut results: Vec<_> = scan.processes.values().collect();
        results.sort_by_key(|result| result.pid);
        for result in results {
            println!(
                "pid: {}\nname: {}\npath: {}\n",
                result.pid,
                result.name.to_string_lossy(),
                result.path.display()
            );
        }
        if cli.kill {
            println!(
                "{}",
                "WARNING: Forcefully terminating these processes can cause data loss."
                    .bold()
                    .yellow()
            );
            if confirm_termination(&mut io::stdin().lock(), &mut io::stdout().lock())? {
                let report = kill_processes(&scan.processes);
                for (pid, error) in &report.failures {
                    eprintln!("Failed to terminate PID {pid}: {error}");
                }
                println!(
                    "Termination requested successfully for {} process(es).",
                    report.succeeded
                );
                anyhow::ensure!(
                    report.failures.is_empty(),
                    "Failed to terminate {} process(es)",
                    report.failures.len()
                );
            } else {
                println!("Operation cancelled by user.");
            }
        }
    }
    Ok(scan_status(partial))
}

fn scan_status(partial: bool) -> std::process::ExitCode {
    if partial {
        std::process::ExitCode::from(2)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn confirm_termination(
    input: &mut impl io::BufRead,
    output: &mut impl Write,
) -> anyhow::Result<bool> {
    write!(output, "Proceed with termination? (y/N): ")?;
    output
        .flush()
        .context("Failed to flush the confirmation prompt")?;
    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .context("Failed to read confirmation")?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

#[derive(Default)]
struct KillReport {
    succeeded: usize,
    failures: Vec<(u32, String)>,
}

fn kill_processes(processes: &HashMap<u32, ProcessResult>) -> KillReport {
    terminate_all(processes.values(), |process| {
        process_ext::kill_process_by_pid(process.pid)
    })
}

fn terminate_all<'a>(
    processes: impl IntoIterator<Item = &'a ProcessResult>,
    mut terminate: impl FnMut(&ProcessResult) -> anyhow::Result<()>,
) -> KillReport {
    let mut report = KillReport::default();
    for process in processes {
        match terminate(process) {
            Ok(()) => report.succeeded += 1,
            Err(error) => report.failures.push((process.pid, format!("{error:#}"))),
        }
    }
    report
}
struct ScanResult {
    processes: HashMap<u32, ProcessResult>,
    diagnostics: diagnostics::Diagnostics,
}

fn find_locker(cli: &Cli) -> anyhow::Result<ScanResult> {
    let reference_path = &cli.path;

    if reference_path.as_os_str().is_empty() {
        return Err(anyhow::anyhow!("Path cannot be empty"));
    }

    if !reference_path.exists() {
        return Err(anyhow::anyhow!(
            "Path does not exist: {}",
            reference_path.display()
        ));
    }

    let nt_path = path_ext::win32_path_to_nt_path(reference_path)
        .with_context(|| "Failed to convert Win32 path to NT path")?;

    let mut process_results = HashMap::<u32, ProcessResult>::new();
    let mut diagnostics = diagnostics::Diagnostics::default();

    let handle_infos = handle_ext::enum_handles().with_context(|| "Failed to enumerate handles")?;

    for handle_info in handle_infos {
        if path_ext::is_same_or_ancestor_of(&nt_path, &handle_info.nt_path) {
            let pid = handle_info.pid;
            let name =
                process_ext::pid_to_process_name(pid).unwrap_or_else(|_| OsString::from("unknown"));
            let path = process_ext::pid_to_process_full_path(pid)
                .unwrap_or_else(|_| PathBuf::from("unknown"));
            let process_result = ProcessResult { pid, name, path };
            process_results.insert(pid, process_result);
        }
    }

    let proces_infos = match process_ext::enum_processes() {
        Ok(scan) => {
            diagnostics.merge(scan.diagnostics);
            scan.processes
        }
        Err(error) => {
            diagnostics.record(format!("Process enumeration failed: {error:#}"));
            Vec::new()
        }
    };
    for process_info in proces_infos {
        for module in &process_info.modules {
            if path_ext::is_same_or_ancestor_of(&nt_path, module) {
                let process_result = ProcessResult {
                    pid: process_info.pid,
                    name: process_info.process_name.clone(),
                    path: process_info.process_full_path.clone(),
                };
                process_results.insert(process_info.pid, process_result);
            }
        }
    }

    Ok(ScanResult {
        processes: process_results,
        diagnostics,
    })
}

#[derive(Debug)]
struct ProcessResult {
    pid: u32,
    name: OsString,
    path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_summary_keeps_all_failures_and_successes() {
        let processes: Vec<_> = [17, 42, 99]
            .into_iter()
            .map(|pid| ProcessResult {
                pid,
                name: OsString::from("test"),
                path: PathBuf::from("test"),
            })
            .collect();
        let mut visited = Vec::new();
        let report = terminate_all(&processes, |process| {
            visited.push(process.pid);
            if process.pid == 42 {
                anyhow::bail!("access denied");
            }
            Ok(())
        });
        assert_eq!(visited, [17, 42, 99]);
        assert_eq!(report.succeeded, 2);
        assert_eq!(report.failures, [(42, "access denied".into())]);
    }

    #[test]
    fn confirmation_defaults_to_no_and_requires_explicit_yes() {
        for (answer, expected) in [("", false), ("n\n", false), ("yes\n", false), ("Y\n", true)] {
            assert_eq!(
                confirm_termination(&mut io::Cursor::new(answer), &mut Vec::new()).unwrap(),
                expected
            );
        }
        assert_eq!(scan_status(false), std::process::ExitCode::SUCCESS);
        assert_eq!(scan_status(true), std::process::ExitCode::from(2));
    }
}
