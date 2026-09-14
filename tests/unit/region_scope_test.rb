#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Contract test for RegionScope#resolve_region_scope.
#
# The contract this locks down:
#
#   ["us-east-1", ...] -> exactly those, no error
#   ["*"]              -> every enabled region in the partition
#   []                 -> ERROR, and NO regions
#
# The third case is the point. An empty input used to mean "discover everything",
# while the same empty input meant "current region only" in another profile — one
# knob, two opposite meanings, and nothing in the evidence saying which happened.
# Refusing to guess is what makes the scan scope auditable.
#
# Tested in the FAILING direction as well as the passing one. A resolver hardwired
# to return an error would satisfy a one-sided test, and so would one that never
# errors — both are checked here.
#
# Run: ruby tests/unit/region_scope_test.rb   (needs `cinc-auditor vendor` first)

# Region fixtures. Named rather than repeated inline so the intent of each one is
# readable at its use site: which regions the account "has", which the caller
# asks for, and which is deliberately outside the discovered set.
PRIMARY        = "us-east-1"
SECONDARY      = "us-west-2"
TERTIARY       = "eu-west-1"
UNDISCOVERED   = "eu-central-1"
STUB_CREDENTIAL = "stubbed"

ENV["AWS_REGION"]            ||= PRIMARY
ENV["AWS_ACCESS_KEY_ID"]     ||= STUB_CREDENTIAL
ENV["AWS_SECRET_ACCESS_KEY"] ||= STUB_CREDENTIAL

require "inspec"
require "aws-sdk-core"
require "aws-sdk-ec2"

VENDOR = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
abort "FATAL: no vendored inspec-aws — run `cinc-auditor vendor . --overwrite` first." if VENDOR.nil?
$LOAD_PATH.unshift(VENDOR)
require "aws_backend"
eval(File.read("libraries/_region_scope_helpers.rb"), TOPLEVEL_BINDING, "libraries/_region_scope_helpers.rb") # rubocop:disable Security/Eval

DISCOVERED = [PRIMARY, SECONDARY, TERTIARY].freeze
FAILURES = []

class Probe
  include RegionScope
end

def check(desc, actual, expected)
  if actual == expected
    puts "  PASS  #{desc}"
  else
    puts "  FAIL  #{desc}\n        expected #{expected.inspect}\n        got      #{actual.inspect}"
    FAILURES << desc
  end
end

Aws.config[:stub_responses] = true
Aws.config[:ec2] = { stub_responses: {
  describe_regions: { regions: DISCOVERED.map { |r| { region_name: r } } },
} }

aws = AwsConnection.new({ client_args: {} })
probe = Probe.new

# --- an explicit list is honoured verbatim, and does NOT discover
regions, error = probe.resolve_region_scope(aws, [PRIMARY, UNDISCOVERED])
check("explicit list -> those regions",        regions, [PRIMARY, UNDISCOVERED])
check("explicit list -> no error",             error,   nil)

# --- blank entries are stripped; "" must never become a region named ""
regions, error = probe.resolve_region_scope(aws, [PRIMARY, "", "  "])
check("blank entries stripped",                regions, [PRIMARY])
check("blank entries -> no error",             error,   nil)

# --- the explicit sweep sentinel discovers
regions, error = probe.resolve_region_scope(aws, ["*"])
check("\"*\" -> discovers every region",       regions, DISCOVERED)
check("\"*\" -> no error",                     error,   nil)

# --- EMPTY MUST FAIL. This is the case the whole change exists for.
regions, error = probe.resolve_region_scope(aws, [])
check("empty -> no regions",                   regions, [])
check("empty -> error is set",                 !error.nil?, true)
check("empty -> error names the remedy",       error.to_s.include?("scan_regions"), true)
puts "  note  #{error}"

# --- whitespace-only is the same as empty, not a region
regions, error = probe.resolve_region_scope(aws, ["  ", ""])
check("whitespace-only -> no regions",         regions, [])
check("whitespace-only -> error is set",       !error.nil?, true)

puts
if FAILURES.empty?
  puts "region scope: OK (explicit, sweep, and the refusal — both directions)"
  exit 0
end
warn "region scope: #{FAILURES.size} FAILURE(S): #{FAILURES.join(', ')}"
exit 1
