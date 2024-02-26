{
  outputs = { self, flake-utils, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cilium-cli
            hubble
            kubectl
            kubernetes-helm
            talosctl
            yq-go
          ];
        };
      }
    );
}
