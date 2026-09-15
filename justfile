#!/usr/bin/env just --justfile

default: check

check:
    cargo test -p moq-trace --all-features
    cargo test -p quic-trace --all-features
    PYTHONPATH=python/src${PYTHONPATH:+:$PYTHONPATH} python -m unittest discover -s python/tests -v
    cmake -S . -B target/cmake -DBUILD_TESTING=ON
    cmake --build target/cmake
    ctest --test-dir target/cmake --output-on-failure
    ruff check python
    ruff format --check python

fix:
    cargo fmt --all
    ruff check --fix python
    ruff format python

# The measurement peers. They build against the sibling moq repository, so they are
# excluded from the workspace and from `check`, which must pass on its own.
moq-bench-build:
    cargo build --manifest-path moq-bench/Cargo.toml --features lttng

moq-bench-check:
    cargo test --manifest-path moq-bench/Cargo.toml --all-features
    cargo fmt --manifest-path moq-bench/Cargo.toml --all --check
    cargo clippy --manifest-path moq-bench/Cargo.toml --all-targets --all-features -- -D warnings

moq-bench-fix:
    cargo fmt --manifest-path moq-bench/Cargo.toml --all
