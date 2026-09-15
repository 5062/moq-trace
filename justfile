#!/usr/bin/env just --justfile

default: check

check:
    cargo test -p quic-trace --all-features
    PYTHONPATH=python/src python -m unittest discover -s python/tests -v
    cmake -S . -B target/cmake -DBUILD_TESTING=ON
    cmake --build target/cmake
    ctest --test-dir target/cmake --output-on-failure
    ruff check python
    ruff format --check python

fix:
    cargo fmt --all
    ruff check --fix python
    ruff format python
