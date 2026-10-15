use std::{env, path::PathBuf};

fn main() {
    let library = pkg_config::Config::new()
        .atleast_version("2.1")
        .probe("babeltrace2")
        .expect("the native decoder requires Babeltrace 2.1 development files");
    let mut builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <babeltrace2/babeltrace.h>")
        .allowlist_function("bt_.*")
        .allowlist_type("bt_.*")
        .allowlist_var("BT_.*")
        .prepend_enum_name(false)
        .derive_debug(false)
        .layout_tests(false);
    for path in library.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }
    builder
        .generate()
        .expect("generate Babeltrace bindings")
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("babeltrace.rs"))
        .expect("write Babeltrace bindings");
}
