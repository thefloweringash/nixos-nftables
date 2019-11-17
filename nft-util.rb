# frozen_string_literal: true

require 'set'
require 'json'
require 'optparse'

ChainName = Struct.new(:family, :table, :chain) do
  def self.from_chain(obj)
    new(*obj.fetch_values('family', 'table', 'name'))
  end

  def self.from_rule(obj)
    new(*obj.fetch_values('family', 'table', 'chain'))
  end

  def self.from_chain_spec(obj)
    from_rule(obj)
  end
end

# State is unparsed raw objects out of nftables
class State
  def initialize(json)
    @json = json
  end

  def chains
    get_entities('chain')
  end

  def rules
    get_entities('rule')
  end

  def get_entities(type)
    return enum_for(:get_entities, type) unless block_given?

    @json['nftables'].each { |x| yield x[type] if x.key?(type) }
  end

  def self.from_json_file(file)
    new(File.open(file) { |f| JSON.load(f) })
  end
end

Hook = Struct.new(:family, :table, :chain, :hook) do
  def chain_name
    ChainName.new(family, table, chain)
  end

  def self.from_json(obj)
    new(*obj.fetch_values('family', 'table', 'chain', 'hook'))
  end
end

HooksFile = Struct.new(:hooks) do
  def self.from_json_file(file)
    new(File.open(file) { |f| JSON.load(f) }.map(&Hook.method(:from_json)))
  end
end

ChainsFile = Struct.new(:chain_names) do
  def self.from_json_file(file)
    new(File.open(file) { |f| JSON.load(f) }.map(&ChainName.method(:from_chain_spec)))
  end
end

# Minimal parser, consider using thor
def parse_options!
  options = {}
  OptionParser.new do |opts|
    opts.accept(State, &State.method(:from_json_file))
    opts.accept(HooksFile, &HooksFile.method(:from_json_file))
    opts.accept(ChainsFile, &ChainsFile.method(:from_json_file))

    opts.on('-s', '--state STATE', State)
    opts.on('-h', '--hooks HOOKS', HooksFile)
    opts.on('-c', '--chains CHAINS', ChainsFile)
    opts.on('-o', '--old-chains CHAINS', ChainsFile)
  end.parse!(into: options)

  raise "Expected single verb, saw #{ARGV}" if ARGV.length != 1

  return ARGV[0], options
end

def main
  verb, options = parse_options!

  case verb
  when 'ensure-hooks'
    ensure_hooks(state: options.fetch(:state),
                 hooks: options.fetch(:hooks).hooks)
  when 'remove-chains'
    remove_chains(state: options.fetch(:state),
                  chain_names: options.fetch(:chains).chain_names)
  when 'remove-stale-chains'
    remove_stale_chains(state: options.fetch(:state),
                        chain_names: options.fetch(:chains).chain_names,
                        old_chain_names: options.fetch(:"old-chains").chain_names)
  else
    raise "Unexpected verb: #{verb}"
  end
end

def rule_is_trivial_jump_to?(rule, target)
  return false if rule['expr'].length != 2
  return false unless rule['expr'][0].key?('counter')

  rule['expr'][1] == { 'jump' => { 'target' => target } }
end

def rule_jump_target(rule)
  rule['expr'].each do |e|
    return e['jump']['target'] if e.key?('jump')
  end
  nil
end

def ensure_hooks(state:, hooks:)
  rules_by_chain = state.rules.group_by(&ChainName.method(:from_rule))

  required_hooks = hooks.reject do |hook|
    rules_to_check = rules_by_chain[hook.chain_name]

    next false if rules_to_check.nil?

    rules_to_check.detect do |rule|
      rule_is_trivial_jump_to?(rule, hook.hook)
    end
  end

  required_hooks.each do |hook|
    puts "add rule #{hook.family} #{hook.table} #{hook.chain} counter jump #{hook.hook}"
  end
end

def remove_stale_chains(state:, old_chain_names:, chain_names:)
  remove_chains(state: state, chain_names: chain_names - old_chain_names)
end

def remove_chains(state:, chain_names:)
  existing_chains = state.chains.each_with_object({}) do |chain, h|
    h[ChainName.from_chain(chain)] = chain
  end

  target_chains = []
  target_chain_names = []

  chain_names.each do |chain_name|
    if (chain = existing_chains[chain_name])
      target_chains << chain
      target_chain_names << chain_name
    end
  end

  # find all rules referring to removed chains and remove them
  target_rules = state.rules.select do |rule|
    jump_target = rule_jump_target(rule)
    next false if jump_target.nil?

    absolute_target_chain_name =
      ChainName.from_rule(rule).tap { |x| x.chain = jump_target }

    target_chain_names.include?(absolute_target_chain_name)
  end

  # Remove all rules referring to our owned chains
  target_rules.each do |r|
    puts "delete rule #{r['family']} #{r['table']} #{r['chain']} handle #{r['handle']}"
  end

  # then remove the chains
  target_chains.each do |c|
    puts "delete chain #{c['family']} #{c['table']} handle #{c['handle']}"
  end
end

main
