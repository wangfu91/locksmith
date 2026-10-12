fn main() {
    let manifest = "packaging/windows/locksmith.manifest";
    println!("cargo:rerun-if-changed={manifest}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let path =
            std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(manifest);
        println!("cargo:rustc-link-arg-bin=locksmith=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=locksmith=/MANIFESTINPUT:{}",
            path.display()
        );
    }
}
