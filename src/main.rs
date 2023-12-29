mod handle_ext;
mod path_ext;
mod process_ext;
mod safe_handle;
mod to_string;

fn main() {
    //enum_processes();

    //process_ext::enum_process_modules(23936).unwrap();

    let pid = 29496u32;
    match process_ext::pid_to_process_name(pid) {
        Ok(path) => println!("name: {}", path),
        Err(e) => println!("pid_to_process_name failed, e: {:?}", e),
    }

    match process_ext::pid_to_process_full_path(pid) {
        Ok(path) => println!("path: {}", path),
        Err(e) => println!("pid_to_process_full_path failed, e: {:?}", e),
    }
}
