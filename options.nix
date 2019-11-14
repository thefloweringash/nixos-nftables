# Extracted from upstream, since I couldn't find a way to export it.
{ lib }:

with lib;

{
  commonOptions = {
    allowedTCPPorts = mkOption {
      type = types.listOf types.port;
      default = [ ];
      apply = canonicalizePortList;
      example = [ 22 80 ];
      description =
        '' 
          List of TCP ports on which incoming connections are
          accepted.
        '';
    };

    allowedTCPPortRanges = mkOption {
      type = types.listOf (types.attrsOf types.port);
      default = [ ];
      example = [ { from = 8999; to = 9003; } ];
      description =
        '' 
          A range of TCP ports on which incoming connections are
          accepted.
        '';
    };

    allowedUDPPorts = mkOption {
      type = types.listOf types.port;
      default = [ ];
      apply = canonicalizePortList;
      example = [ 53 ];
      description =
        ''
          List of open UDP ports.
        '';
    };

    allowedUDPPortRanges = mkOption {
      type = types.listOf (types.attrsOf types.port);
      default = [ ];
      example = [ { from = 60000; to = 61000; } ];
      description =
        ''
          Range of open UDP ports.
        '';
    };
  };
}
