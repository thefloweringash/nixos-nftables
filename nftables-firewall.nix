{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types flip concatMapStrings optionalString
    concatStrings mapAttrsToList mapAttrs optionals concatMap;

  inherit (import ./options.nix { inherit lib; }) commonOptions;

  cfg = config.networking.firewall;

  # This is ordered to match iptables-save, so the diffs are smaller.
  # Order is not important once this module is no longer an active
  # porting job.
  defaultConfigs = [
    "ipv4-nat.nft"
    "ipv4-raw.nft"
    "ipv4-filter.nft"
    # "ipv4-mangle.nft"
  ] ++ optionals config.networking.enableIPv6 [
    "ipv6-filter.nft"
    # "ipv6-mangle.nft"
    # "ipv6-nat.nft"
    "ipv6-raw.nft"
  ];

  families = [ "ip" ] ++ optionals config.networking.enableIPv6 [ "ip6" ];

  inherit (config.boot.kernelPackages) kernel;

  kernelHasRPFilter = ((kernel.config.isEnabled or (x: false)) "IP_NF_MATCH_RPFILTER") || (kernel.features.netfilterRPFilter or false);

  defaultInterface = { default = mapAttrs (name: value: cfg.${name}) commonOptions; };
  allInterfaces = defaultInterface // cfg.interfaces;

  add46Entity = table: ent: ''
    table ip ${table} {

    ${ent "v4"}

    }

    ${optionalString config.networking.enableIPv6 ''
      table ip6 ${table} {

      ${ent "v6"}

      }
    ''}
  '';

  nixos-fw-accept = family: ''
    # The "nixos-fw-accept" chain just accepts packets.

    chain nixos-fw-accept {
      counter accept
    }
  '';

  nixos-fw-refuse = family: ''
    # The "nixos-fw-refuse" chain rejects or drops packets.

    chain nixos-fw-refuse {

      ${if cfg.rejectPackets then ''
        # Send a reset for existing TCP connections that we've
        # somehow forgotten about.  Send ICMP "port unreachable"
        # for everything else.
        tcp flags & (fin | syn | rst | ack) != syn counter reject with tcp reset
        counter reject
      '' else ''
        counter drop
      ''}

    }
  '';

  nixos-fw-log-refuse = family: ''
    # The "nixos-fw-log-refuse" chain performs logging, then
    # jumps to the "nixos-fw-refuse" chain.

    chain nixos-fw-log-refuse {

      ${optionalString cfg.logRefusedConnections ''
        tcp flags & (fin | syn | rst | ack) == syn \
          counter log prefix "refused connection: " level info
      ''}

      ${optionalString (cfg.logRefusedPackets && !cfg.logRefusedUnicastsOnly) ''
        meta pkttype broadcast counter log prefix "refused broadcast: " level info
        meta pkttype multicast counter log prefix "refused multicast: " level info
      ''}

      meta pkttype != host counter jump nixos-fw-refuse

      ${optionalString cfg.logRefusedPackets ''
        counter log prefix "refused packet: " level info
      ''}

      counter jump nixos-fw-refuse

    }
  '';

  nixos-fw-rpfilter = family: ''
    # Perform a reverse-path test to refuse spoofers
    # For now, we just drop, as the raw table doesn't have a log-refuse yet
    chain nixos-fw-rpfilter {

      fib saddr . mark . iif oif != 0 counter return

      ${optionalString (family == "v4") ''
        # Allows this host to act as a DHCP4 client without first having to use APIPA
        udp sport 67 udp dport 68 counter return

        # Allows this host to act as a DHCPv4 server
        ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter return
      ''}

      ${optionalString cfg.logReversePathDrops ''
        counter log prefix "rpfilter drop: " level info
      ''}

      counter drop
    }
  '';

  nixos-fw = family: ''
    # The "nixos-fw" chain does the actual work.
    chain nixos-fw {

      # Accept all traffic on the trusted interfaces.
      ${flip concatMapStrings cfg.trustedInterfaces (iface: ''
        iifname "${iface}" counter jump nixos-fw-accept
      '')}

      # Accept packets from established or related connections.
      ct state established,related counter jump nixos-fw-accept

      # Accept connections to the allowed TCP ports.
      ${concatStrings (mapAttrsToList (iface: cfg:
        concatMapStrings (port:
          ''
            ${optionalString (iface != "default") ''iifname "${iface}" ''
            }tcp dport ${toString port} counter jump nixos-fw-accept
          ''
        ) cfg.allowedTCPPorts
      ) allInterfaces)}

      # Accept connections to the allowed TCP port ranges.
      ${concatStrings (mapAttrsToList (iface: cfg:
        concatMapStrings (rangeAttr:
          let range = toString rangeAttr.from + "-" + toString rangeAttr.to; in
          ''
            ${optionalString (iface != "default") ''iifname "${iface}" ''
            }tcp dport ${range} counter jump nixos-fw-accept
          ''
        ) cfg.allowedTCPPortRanges
      ) allInterfaces)}

      # Accept connections to the allowed UDP ports.
      ${concatStrings (mapAttrsToList (iface: cfg:
        concatMapStrings (port:
          ''
            ${optionalString (iface != "default") ''iifname "${iface}" ''
            }udp dport ${toString port} counter jump nixos-fw-accept
          ''
        ) cfg.allowedUDPPorts
      ) allInterfaces)}

      # Accept connections to the allowed UDP port ranges.
      ${concatStrings (mapAttrsToList (iface: cfg:
        concatMapStrings (rangeAttr:
          let range = toString rangeAttr.from + "-" + toString rangeAttr.to; in
          ''
            ${optionalString (iface != "default") ''iifname "${iface}" ''
            }udp dport ${range} counter jump nixos-fw-accept
          ''
        ) cfg.allowedUDPPortRanges
      ) allInterfaces)}

      ${optionalString (family == "v4") ''
        # Optionally respond to ICMPv4 pings.
        ${optionalString cfg.allowPing ''
          icmp type echo-request counter jump nixos-fw-accept
        ''}
      ''}

      ${optionalString (family == "v6") ''
        # Accept all ICMPv6 messages except redirects and node
        # information queries (type 139).  See RFC 4890, section
        # 4.4.
        icmpv6 type nd-redirect counter drop
        meta l4proto 58 counter jump nixos-fw-accept

        # Allow this host to act as a DHCPv6 client
        ip6 daddr fe80::/64 udp dport 546 counter jump nixos-fw-accept
      ''}
    }
  '';

  addFamilies = xs: concatMap (x: map (family: x // { inherit family; }) families) xs;

  createdChains = addFamilies (
    [
      { table = "filter"; chain = "nixos-fw"; }
      { table = "filter"; chain = "nixos-fw-accept"; }
      { table = "filter"; chain = "nixos-fw-refuse"; }
      { table = "filter"; chain = "nixos-fw-log-refuse"; }
    ] ++ optionals cfg.checkReversePath [
      { table = "raw"; chain = "nixos-fw-rpfilter"; }
    ]
  );

  createdChainsJSON = pkgs.writeText "chains.json" (builtins.toJSON createdChains);

  firewallRules = pkgs.writeText "rules.nft" ''
    ${flip concatMapStrings defaultConfigs (configFile: ''
      include "${pkgs.nftables}/etc/nftables/${configFile}"
    '')}

    ${flip concatMapStrings createdChains ({ family, table, chain }: ''
      add chain ${family} ${table} ${chain}
      flush chain ${family} ${table} ${chain}
    '')}

    ${add46Entity "filter" nixos-fw-accept}
    ${add46Entity "filter" nixos-fw-refuse}
    ${add46Entity "filter" nixos-fw-log-refuse}
    ${optionalString cfg.checkReversePath (
      add46Entity "raw" nixos-fw-rpfilter
    )}
    ${add46Entity "filter" nixos-fw}

    ${config.build.debug.nftables.extraCommands}

    add rule ip filter nixos-fw counter jump nixos-fw-log-refuse
    ${optionalString config.networking.enableIPv6 ''
      add rule ip6 filter nixos-fw counter jump nixos-fw-log-refuse
    ''}
  '';

  hooks = addFamilies (
    [ { table = "filter"; chain = "input"; hook = "nixos-fw"; } ]
    ++ optionals cfg.checkReversePath [
      { table = "raw"; chain = "prerouting"; hook = "nixos-fw-rpfilter"; }
    ]
  );

  startRules = pkgs.writeText "start.nft" (flip concatMapStrings hooks (
    { family, table, chain, hook }: ''
      add rule ${family} ${table} ${chain} counter jump ${hook}
    ''
  ));

  hooksJSON = pkgs.writeText "hooks.json" (builtins.toJSON hooks);
in
{
  options = {
    build.debug.nftables = {
      rulesetFile = mkOption { type = types.path; };
      extraCommands = mkOption { type = types.lines; default = ""; };
      hooks = mkOption { type = types.path; };
      chains = mkOption { type = types.path; };
    };
  };

  config = {
    networking.nftables.enable = true;
    networking.nftables.ruleset = lib.mkDefault "";

    systemd.services.new-firewall = {
      after = [ "nftables.service" ];
      requires = [ "nftables.service" ];
      before = [ "network-pre.target" ];
      wants = [ "network-pre.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [
        pkgs.nftables
        (pkgs.writeScriptBin "nft-util" ''
          ${pkgs.ruby}/bin/ruby ${./nft-util.rb} "$@"
        '')
      ];
      serviceConfig = {
        ExecStart = pkgs.writeScript "firewall-start" ''
          #!${pkgs.runtimeShell} -e
          nft --check -f ${firewallRules}
          cat ${firewallRules} ${startRules} | nft -f -
        '';
        ExecReload = pkgs.writeScript "firewall-reload" ''
          #!${pkgs.runtimeShell} -e
          nft --check -f ${firewallRules}

          cd $RUNTIME_DIRECTORY

          nft --json list ruleset > state.json

          nft-util ensure-hooks \
            --state state.json \
            --hooks ${hooksJSON} \
            > ensure.nft

          cat ${firewallRules} ensure.nft | nft -f -
        '';
        ExecStop = pkgs.writeScript "firewall-stop" ''
          #!${pkgs.runtimeShell} -e
          cd $RUNTIME_DIRECTORY

          nft --json list ruleset > state.json

          nft-util remove-chains \
            --state state.json \
            --chains ${createdChainsJSON} \
            > stop.nft

          nft -f stop.nft
        '';

        RuntimeDirectory = "new-firewall";
        Type = "oneshot";
        RemainAfterExit = "true";
      };
    };

    build.debug.nftables = {
      rulesetFile = firewallRules;
      chains = createdChainsJSON;
      hooks = hooksJSON;
    };
  };
}
