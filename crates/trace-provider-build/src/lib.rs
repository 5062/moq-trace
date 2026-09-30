//! Build script support shared by the native LTTng-UST provider crates.
//!
//! A provider crate keeps its schema in `provider/`: `interface.h` declares the
//! payload structs and the C API, `events.tp` the LTTng events, `events.inc` the
//! event list, and `identity.c` the process-wide counters. Everything else is the
//! same for every provider, so it lives here once: the generated Rust bindings,
//! the `lttng-gen-tp` step, and the C source that wraps each event, which CMake
//! builds from the same `provider.c.in` template.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The C source of every provider, with `@PROVIDER@` in place of its name.
const TEMPLATE: &str = include_str!("../provider.c.in");

/// Build the native provider named `provider` from the calling crate's `provider/` directory.
///
/// This writes Rust bindings for `interface.h` to `$OUT_DIR/bindings.rs` and
/// links a static library named `<provider>_provider`. Off Linux it does
/// nothing, because LTTng-UST exists only there and the facades then emit no
/// events.
pub fn build(provider: &str) {
    let directory = Path::new("provider");
    for file in ["interface.h", "events.tp", "events.inc", "identity.c"] {
        println!("cargo:rerun-if-changed={}", directory.join(file).display());
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));

    bindgen::Builder::default()
        .header(directory.join("interface.h").display().to_string())
        .allowlist_function(format!("{provider}_.*"))
        .allowlist_type(format!("{provider}_.*"))
        .allowlist_var(format!("{}_.*", provider.to_uppercase()))
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate Rust bindings for the tracepoint interface")
        .write_to_file(output.join("bindings.rs"))
        .expect("failed to write tracepoint bindings");

    let template = std::env::current_dir()
        .expect("crate directory is available")
        .join(directory.join("events.tp"));
    let status = Command::new("lttng-gen-tp")
        .current_dir(&output)
        .arg(template)
        .arg("-o")
        .arg("events.h")
        .status()
        .expect("failed to execute lttng-gen-tp; install LTTng-UST 2.13 or newer");
    assert!(status.success(), "lttng-gen-tp failed with status {status}");

    let source = output.join("provider.c");
    std::fs::write(&source, TEMPLATE.replace("@PROVIDER@", provider))
        .expect("failed to write the provider source");

    let library = pkg_config::Config::new()
        .atleast_version("2.13")
        .probe("lttng-ust")
        .expect("failed to locate LTTng-UST 2.13 or newer with pkg-config");
    let mut build = cc::Build::new();
    build
        .file(&source)
        .file(directory.join("identity.c"))
        .include(directory)
        .include(&output);
    for include in library.include_paths {
        build.include(include);
    }
    build.compile(&format!("{provider}_provider"));
}
