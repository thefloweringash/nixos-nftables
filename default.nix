{ nixpkgs ? import <nixpkgs> {} }:


with nixpkgs;
with lib;

let
   canonicalise = name: rules: vmTools.runInLinuxVM (
     runCommand "canonicalise-${name}" {
       nativeBuildInputs = [ nftables jq ];
       inherit rules;
     } ''
       for r in $rules; do
         nft -f $r
       done

       nft -s list ruleset > $out/rules.nft

       nft -s --json list ruleset | jq -f ${./nftables-json-canonicaliser.jq} > $out/rules.json
     ''
  );

  translate = name: cfg:
    let
      migrated = vmTools.runInLinuxVM (
        runCommand "automatically-migrate-${name}" {
          nativeBuildInputs = [ iptables-legacy ];
        } ''
          script="${(nixos cfg).config.systemd.services.firewall.serviceConfig.ExecStart}"
          script=''${script#@}
          eval "$script"

          mkdir -p $out/{iptables,nftables}

          iptables-save > $out/iptables/ip4
          ip6tables-save > $out/iptables/ip6

          ${iptables-nftables-compat}/bin/iptables-restore-translate \
            -f $out/iptables/ip4 | tee $out/nftables/ip4

          ${iptables-nftables-compat}/bin/ip6tables-restore-translate \
            -f $out/iptables/ip6 | tee $out/nftables/ip6
          ''
      );
    in canonicalise name [ "${migrated}/nftables/ip4" "${migrated}/nftables/ip6" ];

  generate = name: cfg:
    let nixosConfig = { imports = [ cfg ./nftables-firewall.nix ./nftables-nat.nix ]; };
    in canonicalise name ((nixos nixosConfig).config.build.debug.nftables.rulesetFile);

  diffConfigs = cfgs:
    runCommand "diff" {
      nativeBuildInputs = [ diffoscope ];
    } ''

      mkdir -p $out/{translated,generated}
      ${concatStrings (flip mapAttrsToList cfgs (name: cfg: ''
        cp ${translate name cfg}/rules.json $out/translated/${name}.json
        cp ${generate name cfg}/rules.json  $out/generated/${name}.json
      ''))}

      rc=0
      diffoscope --html $out/diff.html \
        --no-default-limits --output-empty \
        $out/translated $out/generated || rc=$?
      if [ $rc -ne 1 ] && [ $rc -ne 0 ]; then
        exit $rc
      fi
    '';

  testCases = {
    empty = {};

    nov6 = {
      networking.enableIPv6 = false;
    };

    rejectAndLog = {
      networking.firewall = {
        rejectPackets = true;
        logRefusedPackets = true;
        logRefusedUnicastsOnly = false;
        logReversePathDrops = true;
      };
    };

    acceptingPorts = {
      networking.firewall = {
        trustedInterfaces = [ "dummy-trusted" ];
        allowPing = true;
        # pingLimit = "???";
        allowedUDPPorts = [ 1001 ];
        allowedTCPPorts = [ 1002 ];
        allowedTCPPortRanges = [ { from = 1100; to = 1105; } ];
        allowedUDPPortRanges = [ { from = 1200; to = 1205; } ];
        interfaces.dummy0 = {
          allowedUDPPorts = [ 2001 ];
          allowedTCPPorts = [ 2002 ];
          allowedTCPPortRanges = [ { from = 2100; to = 2105; } ];
          allowedUDPPortRanges = [ { from = 2200; to = 2205; } ];
        };
      };
    };

    natMasquerade = {
      networking.nat = {
        internalInterfaces = [ "eth0" ];
        externalInterface = "eth1";
      };
    };

    natFull = {
      networking.nat = {
        enable = true;
        internalInterfaces = [ "eth0" ];
        internalIPs = [ "192.168.1.0/24" ];
        externalInterface = "eth1";
        externalIP = "203.0.113.123";
        forwardPorts = let
          fwds = [
            { sourcePort = 1000; destination = "10.0.0.1"; proto = "tcp"; }
            { sourcePort = 1001; destination = "10.0.0.1"; proto = "udp"; }
            { sourcePort = "2000:2999"; destination = "10.0.0.1"; proto = "tcp"; }
            { sourcePort = "3000:3999"; destination = "10.0.0.1"; proto = "udp"; }
            { sourcePort = "4000:4999"; destination = "10.0.0.1:14000-14999"; proto = "tcp"; }
            { sourcePort = "5000:5999"; destination = "10.0.0.1:15000-15999"; proto = "udp"; }
          ];
          loopbackableFwds = [
            { sourcePort = 1002; destination = "10.0.0.1:80"; proto = "tcp"; }
            { sourcePort = 1003; destination = "10.0.0.1:80"; proto = "udp"; }
          ]; in (
            fwds
            ++ loopbackableFwds
            ++ map (x: x // { loopbackIPs = [ "55.1.2.3" ]; }) loopbackableFwds
          );

        dmzHost = "10.0.0.2";
      };
    };

    # TODO: nat without firewall
  };

in
{
  diff = diffConfigs testCases;

  translated = mapAttrs translate testCases;

  generated = mapAttrs generate testCases;
}
