{
  description = "TCP Brutal - TCP congestion control algorithm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      mkTcpBrutal = pkgs: kernel: pkgs.stdenv.mkDerivation {
        pname = "tcp-brutal";
        version = self.shortRev or self.dirtyShortRev or "unknown";
        src = ./.;
        nativeBuildInputs = kernel.moduleBuildDependencies;
        makeFlags = kernel.makeFlags ++ [
          "KERNEL_RELEASE=${kernel.modDirVersion}"
          "KERNEL_DIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
          "INSTALL_MOD_DIR=extra"
        ];
        buildPhase = ''
          runHook preBuild
          make ''${makeFlagsArray[@]} -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M=$(pwd) modules
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          make ''${makeFlagsArray[@]} -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M=$(pwd) INSTALL_MOD_PATH=$out modules_install
          runHook postInstall
        '';
        meta = with pkgs.lib; {
          description = "TCP Brutal congestion control algorithm";
          homepage = "https://github.com/apernet/tcp-brutal";
          license = licenses.gpl3Only;
          platforms = platforms.linux;
        };
      };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in {
        packages.default = mkTcpBrutal pkgs pkgs.linuxPackages.kernel;
        lib.mkTcpBrutal = mkTcpBrutal pkgs;
      }
    ) // {
      nixosModules.default = { config, lib, pkgs, ... }: {
        options.boot.tcp-brutal.enable = lib.mkEnableOption "tcp-brutal kernel module";
        config = lib.mkIf config.boot.tcp-brutal.enable {
          boot.extraModulePackages = [ (self.outputs.lib.${pkgs.system}.mkTcpBrutal config.boot.kernelPackages.kernel) ];
          boot.kernelModules = [ "brutal" ];
        };
      };
    };
}
