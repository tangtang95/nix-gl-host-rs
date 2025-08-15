{
  description = "Gluing host OpenGL drivers to a Nix-built binary";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs @ {
    self,
    flake-parts,
    crane,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      flake = {
        overlays.default = final: prev: {
          nix-gl-host = self.packages.${prev.system}.default;
        };
      };

      perSystem = {system, ...}: let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [(import inputs.rust-overlay)];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        commonArgs = let
          includeTestFixtures = path: _type: builtins.match ".*tests/fixtures/.*$" path != null;
        in {
          src =
            pkgs.lib.cleanSourceWith
            {
              src = ./.;
              filter = path: type: (includeTestFixtures path type) || (craneLib.filterCargoSources path type);
            };
          strictDeps = true;
        };

        nix-gl-host = craneLib.buildPackage (commonArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly commonArgs;

            postPatch = ''
              sed -i 's|@patchelf-bin@|${pkgs.patchelf}/bin/patchelf|g' src/main.rs
              sed -i 's|const IN_NIX_STORE: bool = false;|const IN_NIX_STORE: bool = true;|g' src/main.rs
            '';
            meta.mainProgram = "nixglhost";
          });
      in {
        packages.default = nix-gl-host;

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
        };

        checks = {
          inherit nix-gl-host;
        };
      };
    };
}
