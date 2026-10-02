// Links the BSan-instrumented zlib-ng that Bun vendors (built by native/build-clibs.sh).
fn main() {
    let dir = std::env::var("BSAN_CLIBS").unwrap_or("/workspaces/bsan-bun/native/out/clibs".into());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rerun-if-env-changed=BSAN_CLIBS");
}
