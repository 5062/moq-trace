{
  description = "QUIC tracing toolkit";

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
            pyarrow
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
          ];
          hardeningDisable = [ "fortify" ];
        };

        formatter = pkgs.nixfmt-tree;
      }
    );
}
