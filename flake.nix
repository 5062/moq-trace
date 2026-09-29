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
            babeltrace2
            duckdb
            matplotlib
            pyarrow
            pydantic
          ]
        );
        moqTracePackage = pkgs.python3Packages.buildPythonApplication {
          pname = "moq-trace";
          version = "0.1.0";
          pyproject = true;
          src = ./python;
          build-system = [ pkgs.python3Packages.setuptools ];
          dependencies = with pkgs.python3Packages; [
            babeltrace2
            duckdb
            matplotlib
            pyarrow
            pydantic
          ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postFixup = ''
            # ssh is appended rather than prepended: the host's own ssh carries the
            # user's configuration, such as jump hosts and Kerberos, that a
            # separately built client may not support.
            wrapProgram $out/bin/moq-trace \
              --prefix PATH : ${
                pkgs.lib.makeBinPath [
                  pkgs.lttng-tools
                  pkgs.openssl
                  pkgs.util-linux
                ]
              } \
              --suffix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]}
          '';
          meta = {
            description = "Capture and analyze MoQ relay latency experiments";
            mainProgram = "moq-trace";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      in
      {
        packages = {
          default = moqTracePackage;
          moq-trace = moqTracePackage;
        };

        apps.moq-trace = {
          type = "app";
          program = "${moqTracePackage}/bin/moq-trace";
          meta = {
            description = "Capture and analyze MoQ relay latency experiments";
          };
        };

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
            openssl
            pkg-config
            python
            ruff
            rustPlatform.bindgenHook
            util-linux
            (writeShellScriptBin "moq-trace" ''
              exec ${python}/bin/python -m moq_trace.cli "$@"
            '')
          ];
          shellHook = ''
            export PYTHONPATH="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/python/src''${PYTHONPATH:+:$PYTHONPATH}"
          '';
          hardeningDisable = [ "fortify" ];
        };

        formatter = pkgs.nixfmt-tree;
      }
    );
}
