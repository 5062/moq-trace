# MoQ trace Python package

Decode CTF events into Arrow batches, verify transport fixtures, and analyze
MoQ and QUIC captures with DuckDB. The CTF reader is a Rust extension linked to Babeltrace 2.1.

Building from source requires Rust, libclang, pkg-config, and Babeltrace 2.1
development files. Babeltrace and its standard plugins are required at runtime.
The toolkit's Nix development shell provides these dependencies.

From the toolkit root, build the development extension with
`nix develop --command just decoder`. To build an installable package, run
`python -m pip install ./python` in that shell. The `bt2` Python bindings are
needed only for the synthetic trace-IR tests.
