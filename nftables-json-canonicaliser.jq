def remove_handles:
  walk(
    if (type == "object") then
       del(.handle)
    else
       .
    end
  );

def downcase_chains:
  if(.chain) then
    .chain.name |= ascii_downcase
  elif(.rule) then
    .rule.chain |= ascii_downcase
  else
    .
  end;


def element_type:
  if .table then "table"
  elif .chain then "chain"
  elif .rule then "rule"
  else "other"
  end;

def group_by_map(f):
  group_by(f)
  | map({ (.[0] | f): .})
  | add;

def seperate_elements:
  group_by_map(element_type);

def rule_owner:
  "family:\(.family)-table:\(.table)-chain:\(.chain)";

.nftables
| remove_handles
| map(downcase_chains)
| seperate_elements
| .table |= sort
| .chain |= sort
| .rule |= group_by_map(.rule | rule_owner)
