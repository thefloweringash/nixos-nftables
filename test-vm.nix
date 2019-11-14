# build me with:
#
#   nixos-rebuild -I nixos-config=test-vm.nix build-vm

{ config, ... }:
{
  imports = [
    ./nftables-firewall.nix
    # ./nftables-nat.nix -- cannot be used, as the in-tree nat module will conflict.
  ];


  config = {
    services.mingetty.autologinUser = "root";

    networking.firewall.enable = false;
    networking.nftables.enable = true;
    networking.nftables.rulesetFile = config.build.debug.nftables.rulesetFile;
  };
}
