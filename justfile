#!/usr/bin/env just --justfile

default: check

check: tracepoints
    moq-trace --help >/dev/null
    cargo test -p moq-trace --all-features
    cargo test -p quic-trace --all-features
    cargo build --example facade_contract -p moq-trace --all-features
    cmake -S . -B target/cmake --fresh -DBUILD_TESTING=ON
    cmake --build target/cmake
    PYTHONPATH=python/src${PYTHONPATH:+:$PYTHONPATH} python python/checks/facade_contract.py
    PYTHONPATH=python/src${PYTHONPATH:+:$PYTHONPATH} python -m unittest discover -s python/tests -v
    ctest --test-dir target/cmake --output-on-failure
    just package
    ruff check python
    ruff format --check python

# Assert the LTTng providers survive the link and reach a capture.
#
# LTTng-UST registers the providers by walking the linker-synthesized
# __start/__stop_lttng_ust_tracepoints_ptrs symbols. LLD collects a section that
# only those symbols reach under --gc-sections, and rustc links with LLD, which
# leaves the providers registering nothing while `lttng list` still reports
# every event. Inspecting a real binary and reading a trace back is the only way
# to catch that: any in-process check would keep the section alive by itself.
tracepoints:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --example tracepoint_smoke -p moq-trace --all-features
    binary=target/debug/examples/tracepoint_smoke
    if ! command -v readelf >/dev/null; then
        echo "skipping the tracepoint link check: readelf is unavailable"
        exit 0
    fi
    sections=$(readelf -SW "$binary")
    grep -qE 'lttng_ust_tracepoints_ptrs +PROGBITS' <<<"$sections"
    symbols=$(readelf -sW "$binary")
    for symbol in moq_object_start moq_object_phase moq_object_end; do
        grep -q "lttng_ust_tracepoint_ptr_moq_trace___$symbol" <<<"$symbols"
    done
    if ! command -v lttng >/dev/null || ! command -v babeltrace2 >/dev/null; then
        echo "skipping the tracepoint capture check: lttng is unavailable"
        exit 0
    fi
    session="moq-trace-check-$$"
    output="target/tracepoints/$session"
    trap 'lttng destroy "$session" >/dev/null 2>&1 || true' EXIT
    lttng create "$session" --output "$output"
    lttng enable-event -u -a
    lttng start
    "$binary"
    lttng stop
    lttng destroy "$session" >/dev/null
    trap - EXIT
    events=$(babeltrace2 "$output")
    for event in moq_object_start moq_object_phase moq_object_end; do
        grep -q "moq_trace:$event" <<<"$events"
    done

# Consume the installed CMake packages from separate prefixes.
#
# moq_trace::cpp re-exports the quic_trace targets, so its package config has to
# resolve quic_trace with find_dependency. Reaching into a sibling directory
# instead only works while both packages share one prefix, and a relay that
# installs the toolkit into a separate prefix then fails to configure.
package:
    #!/usr/bin/env bash
    set -euo pipefail
    cmake -S . -B target/cmake -DBUILD_TESTING=ON >/dev/null
    cmake --build target/cmake
    prefix_moq="$PWD/target/package/moq"
    prefix_quic="$PWD/target/package/quic"
    cmake --install target/cmake --prefix "$prefix_moq" --component moq_trace
    cmake --install target/cmake --prefix "$prefix_quic" --component quic_trace
    cmake -S cpp/tests/package -B target/package/consumer --fresh -DCMAKE_PREFIX_PATH="$prefix_moq;$prefix_quic"
    cmake --build target/package/consumer
    "$PWD/target/package/consumer/consumer"
    export PKG_CONFIG_PATH="$prefix_moq/lib/pkgconfig:$prefix_quic/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    pkg-config --exists moq_trace
    pkg-config --cflags --libs moq_trace | grep -q -- '-lmoq_trace_provider'
    pkg-config --cflags --libs moq_trace | grep -q -- '-lquic_trace_provider'

# Install the C++ facade and providers into target/install, where C++ relay
# builds such as the Google QUICHE fork find them through pkg-config. A relay
# compiled against an older install emits an older event contract, so its
# build runs this first.
install:
    cmake -S . -B target/install-build -DBUILD_TESTING=OFF
    cmake --build target/install-build
    cmake --install target/install-build --prefix target/install

fix:
    cargo fmt --all
    ruff check --fix python
    ruff format python

# The measurement peers. They build against the instrumented moq branch, so they are
# excluded from the workspace and from `check`, which must pass on its own.
moq-bench-build:
    # Release: a measurement must not carry a debug-built peer's overhead, and the
    # experiment configuration defaults to this path.
    cargo build --release --manifest-path moq-bench/Cargo.toml --features lttng

moq-bench-check:
    cargo test --manifest-path moq-bench/Cargo.toml --all-features
    cargo fmt --manifest-path moq-bench/Cargo.toml --all --check
    cargo clippy --manifest-path moq-bench/Cargo.toml --all-targets --all-features -- -D warnings

moq-bench-fix:
    cargo fmt --manifest-path moq-bench/Cargo.toml --all
