{
  description = "MoQ relay tracing toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
    ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        python = pkgs.python3.withPackages (
          packages: with packages; [
            asyncssh
            babeltrace2
            cryptography
            dpkt
            duckdb
            matplotlib
            numpy
            pyarrow
            pydantic
            build
            setuptools-rust
          ]
        );
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            (rust-bin.stable.latest.default.override { extensions = [ "rustfmt" ]; })
            babeltrace2
            clang
            cmake
            just
            lttng-tools
            lttng-ust
            ninja
            pkg-config
            python
            ruff
            rustPlatform.bindgenHook
            util-linux
            (writeShellScriptBin "moq-trace" ''
              exec ${python}/bin/python -P -m moq_trace.run.cli "$@"
            '')
          ];
          # Entered from the workspace, the git top level is the workspace, and the
          # toolkit is its moq-trace submodule.
          shellHook = ''
            moq_trace_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
            if [ ! -d "$moq_trace_root/python/src/moq_trace" ] && [ -d "$moq_trace_root/moq-trace/python/src/moq_trace" ]; then
              moq_trace_root="$moq_trace_root/moq-trace"
            fi
            export PYTHONPATH="$moq_trace_root/python/src''${PYTHONPATH:+:$PYTHONPATH}"
            unset moq_trace_root
          '';
          hardeningDisable = [ "fortify" ];
        };

        formatter = pkgs.nixfmt-tree;
      }
    );
}
