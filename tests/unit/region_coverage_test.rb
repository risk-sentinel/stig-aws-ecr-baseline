#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Region-coverage harness — proves each custom resource enumerates EVERY
# enabled region, using stubbed AWS clients and no credentials.
#
# Why this exists
# ---------------
# `cinc-auditor check` and `cinc-auditor json` only LOAD a resource. They
# cannot observe which AWS calls it makes, so they cannot tell a resource that
# walks every region from one bound to a single `aws_region` client. The
# second kind does not fail when it misses a region — it finds nothing and
# passes, or routes to Not Applicable, which HDF renders as "does not apply
# here" rather than "we did not look" (cis-aws-foundations-baseline#28).
#
# `exec-evidence.yml` is `workflow_call` only, so no pull request ever execs
# this profile. Without this harness a region fix would ship on evidence that
# structurally cannot detect the bugs it is most likely to introduce.
#
# How it works
# ------------
# `Aws.config[:stub_responses] = true` makes every client stubbed, including
# ones a resource instantiates DIRECTLY as `Aws::EC2::Client.new(region: r)` —
# which is the pattern the per-region fix uses, and which inspec-aws's own
# `opts[:stub_data]` hook cannot reach because that stubs only clients obtained
# via `@aws.aws_client`.
#
# A *callable* stub then records `ctx.client.config.region` on every call, so
# the set of regions a resource actually queried is observable. A resource that
# walks regions touches all of them; a region-blind one touches exactly one.
#
# Run:  ruby tests/unit/region_coverage_test.rb
# Requires `cinc-auditor vendor` to have run (needs the vendored inspec-aws).

ENV["AWS_REGION"]            ||= "us-east-1"
ENV["AWS_ACCESS_KEY_ID"]     ||= "stubbed"
ENV["AWS_SECRET_ACCESS_KEY"] ||= "stubbed"

require "yaml"
require "inspec"
require "aws-sdk-core"
require "aws-sdk-ec2"

# `Aws.config[:<service>]` raises "invalid configuration option" until that
# service's SDK gem is loaded — the config key is registered by the gem, not by
# aws-sdk-core. Each manifest entry therefore declares its service and we
# require `aws-sdk-<service>` before configuring it. A service whose gem is not
# baked into the image is reported rather than silently skipped, because a
# missing gem means that resource is UNCHECKED, which is the condition this
# whole harness exists to make visible.
def require_service!(service)
  require "aws-sdk-#{service}"
  true
rescue LoadError
  false
end

MANIFEST = YAML.safe_load_file(File.join(__dir__, "region_coverage_manifest.yml"))
REGIONS  = MANIFEST.fetch("regions")
OBSERVED = Hash.new { |h, k| h[k] = [] }

# Record the region of every stubbed call, then return a minimal valid shape.
def recorder(key, payload = {})
  lambda do |ctx|
    OBSERVED[key] << ctx.client.config.region
    payload
  end
end

def install_stubs!(entries)
  Aws.config[:stub_responses] = true
  missing = []
  by_service = Hash.new { |h, k| h[k] = {} }
  by_service["ec2"][:describe_regions] = { regions: REGIONS.map { |r| { region_name: r } } }
  entries.each do |e|
    w = e.fetch("watch")
    svc = w.fetch("service")
    missing << "#{e.fetch('resource')} (aws-sdk-#{svc})" unless require_service!(svc)
    # Some operations have required response members — list_analyzers must carry
    # `analyzers`, for example — so an empty payload raises before the resource
    # is ever exercised. `payload:` in the manifest supplies a minimal valid shape.
    payload = (w["payload"] || {}).transform_keys(&:to_sym)
    op = w.fetch("operation").to_sym
    key = "#{svc}/#{op}"
    by_service[svc][op] = recorder(key, payload)
  end
  by_service.each do |svc, stubs|
    next if svc != "ec2" && !Aws.constants.any? { |c| c.to_s.casecmp?(svc) }
    Aws.config[svc.to_sym] = { stub_responses: stubs }
  end
  missing
end

def load_profile_libraries!
  vendor = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
  abort "FATAL: no vendored inspec-aws found — run `cinc-auditor vendor . --overwrite` first." if vendor.nil?
  $LOAD_PATH.unshift(vendor)
  require "aws_backend"

  # Underscore-prefixed helper libraries load first in InSpec's alphabetical
  # order and define the modules resources `include` (e.g. RegionEnumeration).
  # Evaluating a resource without them raises NameError, which would look like a
  # broken resource rather than a harness that loaded things out of order.
  Dir.glob("libraries/_*.rb").sort.each { |f| eval(File.read(f), TOPLEVEL_BINDING, f) } # rubocop:disable Security/Eval
end

missing_gems = install_stubs!(MANIFEST.fetch("resources"))
load_profile_libraries!

unless missing_gems.empty?
  warn "region coverage: #{missing_gems.size} resource(s) UNCHECKED — SDK gem not in the image:"
  missing_gems.each { |m| warn "  - #{m}" }
  warn "An unchecked resource is not a passing resource. Bake the gem or drop the entry deliberately."
  exit 1
end

failures = []
reported = []
unobservable = []

MANIFEST.fetch("resources").each do |e|
  name   = e.fetch("resource")
  status = e.fetch("status", "enforced")
  path   = File.join("libraries", "#{name}.rb")
  unless File.exist?(path)
    failures << "#{name}: libraries/#{name}.rb does not exist (stale manifest entry)"
    next
  end

  eval(File.read(path), TOPLEVEL_BINDING, path) # rubocop:disable Security/Eval
  klass = Object.const_get(e.fetch("klass"))
  args  = (e["args"] || {}).transform_keys(&:to_sym)

  w = e.fetch("watch")
  key = "#{w.fetch('service')}/#{w.fetch('operation')}"
  OBSERVED[key].clear
  begin
    args.empty? ? klass.new : klass.new(**args)
  rescue StandardError => ex
    failures << "#{name}: raised #{ex.class}: #{ex.message}"
    next
  end

  seen   = OBSERVED[key].uniq.sort
  missed = REGIONS.sort - seen

  if missed.empty?
    puts "  PASS         #{name} — queried all #{REGIONS.size} regions"
  elsif status == "unobservable"
    # Not a pass and not a defect: something about the service makes the walk
    # invisible to a stubbed client (endpoint discovery is the usual cause —
    # it fails closed under stub_responses before any operation is reached).
    # Recorded so nobody "fixes" a resource that is already correct, and so the
    # gap in coverage is visible rather than implied by absence.
    reason = e["reason"].to_s
    if reason.empty?
      failures << "#{name}: status `unobservable` requires a `reason`"
    else
      unobservable << "#{name}: #{reason}"
      puts "  UNOBSERVABLE #{name} — #{reason}"
    end
  elsif status == "known_blind"
    reported << "#{name}: queried #{seen.inspect}, never #{missed.inspect}"
    puts "  KNOWN-BLIND  #{name} — queried #{seen.inspect}, never #{missed.inspect}"
  else
    failures << "#{name}: ENFORCED but region-blind — queried #{seen.inspect}, never #{missed.inspect}"
    puts "  FAIL         #{name} — queried #{seen.inspect}, never #{missed.inspect}"
  end
end

puts
unless unobservable.empty?
  puts "#{unobservable.size} resource(s) NOT observable by this harness (not a defect):"
  unobservable.each { |u| puts "  - #{u}" }
  puts
end
unless reported.empty?
  puts "#{reported.size} resource(s) still region-blind (tracked, not gating):"
  reported.each { |r| puts "  - #{r}" }
  puts
end

if failures.empty?
  puts "region coverage: OK (#{MANIFEST.fetch('resources').size} checked, #{reported.size} known-blind, #{unobservable.size} unobservable)"
  exit 0
end

warn "region coverage: #{failures.size} FAILURE(S)"
failures.each { |f| warn "  - #{f}" }
warn ""
warn "A resource marked `enforced` in region_coverage_manifest.yml must query every"
warn "region. If you intentionally made one single-region, say so in the manifest —"
warn "do not delete the entry."
exit 1
