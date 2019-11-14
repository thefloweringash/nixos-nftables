# nftables for NixOS

An implementation of the NixOS firewall (`networking.firewall` and
`networking.nat`) on top of nftables instead of iptables.

Apparently iptables is "legacy", but the most immediate gain is atomic
applications of firewall rules.

This is only the generation step. It does not integrate with a NixOS
system.

## Notes and caveats

This implementation is a precise port of the firewall from NixOS. It
was ported by hand, but is verified against the output of
`iptables-restore-translate`, which converts `iptables-save` output
into an nft script. For debugging and verifying, see the test cases in
`default.nix` and build the diffs via `nix-build -A diff`.

nftables offers matching on `ip`, `ip6`, and `inet`, which supports
both. Users probably want to use the `inet` family, since the
distinction between ipv4 and ipv6 isn't normally important, and the
`ip46helper` is gone. However, this port only translates to `ip` and
`ip6` to mimic `iptables` and `ip6tables`.

In `iptables` every rule implicitly has a counter, while in `nftables`
counters are explicit. In order to match the old behavior (and
`iptables-restore-translate`), all rules have a counter added.

## TODO

 - [ ] Test more
 - [ ] Upstream

