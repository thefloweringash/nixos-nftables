{ config, lib, pkgs, ... }:

let
  inherit (lib) mkIf concatMapStrings optionalString elemAt isInt;

  cfg = config.networking.nat;

  dest = if cfg.externalIP == null then "masquerade" else "snat to ${cfg.externalIP}";

  oifExternal = optionalString (cfg.externalInterface != null)
    ''oifname "${cfg.externalInterface}"'';

  iptablesPortsToNftables = range:
    if isInt range then toString range
    else let m = builtins.match "([0-9]+):([0-9]+)" range;
    in if m == null then range # assume a single port, rely in input validation.
    else "${elemAt m 0}-${elemAt m 1}";

in
{

  config = mkIf config.networking.nat.enable {
    build.debug.nftables.extraCommands = ''
      table ip nat {
        chain nixos-nat-pre {
          # We can't match on incoming interface in POSTROUTING, so
          # mark packets coming from the internal interfaces.
          ${concatMapStrings (iface: ''
            iifname "${iface}" counter meta mark set 1
          '') cfg.internalInterfaces}
        }

        chain nixos-nat-post {
          # NAT the marked packets.
          ${optionalString (cfg.internalInterfaces != []) ''
            ${oifExternal} meta mark 1 counter ${dest}
          ''}

          # NAT packets coming from the internal IPs.
          ${concatMapStrings (range: ''
            ${oifExternal} ip saddr ${range} counter ${dest}
          '') cfg.internalIPs}
        }
      }

    # NAT from external ports to internal ports.
    ${concatMapStrings (fwd:
      let nftSourcePort = iptablesPortsToNftables fwd.sourcePort; in
    ''
      add rule ip nat nixos-nat-pre \
        iifname "${cfg.externalInterface}" ${fwd.proto} dport ${nftSourcePort} \
        counter dnat to ${fwd.destination}

      ${concatMapStrings (loopbackip:
        let
          m                = builtins.match "([0-9.]+):([0-9-]+)" fwd.destination;
          destinationIP    = if (m == null) then throw "bad ip:ports `${fwd.destination}'" else elemAt m 0;
          destinationPorts = if (m == null) then throw "bad ip:ports `${fwd.destination}'" else elemAt m 1;
        in ''
          # Allow connections to ${loopbackip}:${nftSourcePort} from the host itself
          add rule ip nat OUTPUT \
            ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} \
            counter dnat to ${fwd.destination}

          # Allow connections to ${loopbackip}:${nftSourcePort} from other hosts behind NAT
          add rule ip nat nixos-nat-pre \
            ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} \
            counter dnat to ${fwd.destination}

          add rule ip nat nixos-nat-post \
            ip daddr ${destinationIP} ${fwd.proto} dport ${iptablesPortsToNftables destinationPorts} \
            counter snat to ${loopbackip}
        '') fwd.loopbackIPs}
    '') cfg.forwardPorts}

    ${optionalString (cfg.dmzHost != null) ''
      add rule ip nat nixos-nat-pre \
        iifname "${cfg.externalInterface}" \
        counter dnat to ${cfg.dmzHost}
    ''}

    # Append our chains to the nat tables
    add rule ip nat PREROUTING counter jump nixos-nat-pre
    add rule ip nat POSTROUTING counter jump nixos-nat-post
  '';
  };
}
