use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let provider = Path::new("provider");
    let interface = provider.join("interface.h");
    let template = provider.join("events.tp");
    println!("cargo:rerun-if-changed={}", interface.display());
    println!("cargo:rerun-if-changed={}", template.display());
    println!("cargo:rerun-if-changed=provider/interface.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let bindings = bindgen::Builder::default()
        .header(interface.display().to_string())
        .allowlist_function("quic_trace_.*")
        .allowlist_type("quic_trace_.*")
        .allowlist_var("QUIC_TRACE_.*")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate Rust bindings for the tracepoint interface");
    bindings
        .write_to_file(output.join("bindings.rs"))
        .expect("failed to write tracepoint bindings");

    let status = Command::new("lttng-gen-tp")
        .current_dir(&output)
        .arg(
            std::env::current_dir()
                .expect("crate directory is available")
                .join(&template),
        )
        .arg("-o")
        .arg("events.h")
        .status()
        .expect("failed to execute lttng-gen-tp; install LTTng-UST 2.13 or newer");
    assert!(status.success(), "lttng-gen-tp failed with status {status}");

    let library = pkg_config::Config::new()
        .atleast_version("2.13")
        .probe("lttng-ust")
        .expect("failed to locate LTTng-UST 2.13 or newer with pkg-config");
    let mut build = cc::Build::new();
    build
        .file("provider/interface.c")
        .include(provider)
        .include(&output);
    for include in library.include_paths {
        build.include(include);
    }
    build.compile("quic_trace_provider");
}
