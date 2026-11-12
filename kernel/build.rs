fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    println!("cargo:rustc-link-arg-bin=kernel=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed={dir}/linker.ld");
}
