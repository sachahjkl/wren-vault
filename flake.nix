{
  description = "wren-vault: the Vault helper of the Wren browser, a client for Bitwarden accounts behind a pipe protocol (GPL-3.0-only)";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
    rust-overlay = {
      url = "https://flakehub.com/f/oxalica/rust-overlay/0.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "https://flakehub.com/f/cachix/git-hooks.nix/0.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    git-hooks,
    ...
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [rust-overlay.overlays.default];
    };

    # The Rust of Wren's flake: one toolchain for the browser and its helper.
    rust = pkgs.rust-bin.stable."1.99.1";
    rustPlatform = pkgs.makeRustPlatform {
      cargo = rust.minimal;
      rustc = rust.minimal;
    };

    # The SDK is a Git dependency at one revision (Cargo.toml): Nix fetches it with the hashes of Cargo.lock.
    wren-vault = rustPlatform.buildRustPackage {
      pname = "wren-vault";
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
      src = ./.;
      cargoLock = {
        lockFile = ./Cargo.lock;
        allowBuiltinFetchGit = true;
      };
      # the Secret Service store of the tokens links libdbus (found with pkg-config)
      nativeBuildInputs = [pkgs.pkg-config];
      buildInputs = [pkgs.dbus];
      meta = {
        description = "The Vault helper of the Wren browser";
        license = pkgs.lib.licenses.gpl3Only;
        mainProgram = "wren-vault";
      };
    };

    preCommit = git-hooks.lib.${system}.run {
      src = ./.;
      package = pkgs.prek;
      hooks = {
        alejandra.enable = true;
        deadnix.enable = true;
        statix.enable = true;
        rustfmt = {
          enable = true;
          packageOverrides = {
            cargo = rust.default;
            rustfmt = rust.default;
          };
        };
        taplo.enable = true;
      };
    };
  in {
    packages.${system} = {
      inherit wren-vault;
      default = wren-vault;
    };

    # (the package's build runs `cargo test`: the codec, the matching, the state file, the mock-server logins)
    checks.${system} = {
      inherit wren-vault;
      pre-commit = preCommit;
    };

    formatter.${system} = pkgs.alejandra;

    devShells.${system}.default = pkgs.mkShell {
      packages = [rust.default pkgs.pkg-config pkgs.dbus] ++ preCommit.enabledPackages;
      inherit (preCommit) shellHook;
    };
  };
}
