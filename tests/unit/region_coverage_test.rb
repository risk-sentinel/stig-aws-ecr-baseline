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
require_relative "region_coverage_requires"

MANIFEST = YAML.safe_load_file(File.join(__dir__, "region_coverage_manifest.yml"))

# The vendored inspec-aws supplies AwsResourceBase, and it is only reachable
# once its directory is on the load path — hence the glob before the require
# rather than a plain top-of-file require.
VENDOR = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
abort "FATAL: no vendored inspec-aws found — run `cinc-auditor vendor . --overwrite` first." if VENDOR.nil?
$LOAD_PATH.unshift(VENDOR)
require "aws_backend"

# `Aws.config[:<service>]` raises "invalid configuration option" until that
# service's SDK gem is loaded — the config key is registered by the gem, not by
# aws-sdk-core. Which services are needed varies per repository, so the requires
# live in region_coverage_requires.rb next door: literal, top-of-file `require`
# lines, which keeps this shared file identical across every profile repository
# and keeps every require at the top of its own file.
#
# The two can drift, so they are reconciled rather than trusted. A manifest entry
# naming a service with no corresponding require is REPORTED, not skipped: an
# unchecked resource is not a passing resource, and silence here would hide the
# exact condition this harness exists to surface.
MISSING_GEMS = MANIFEST.fetch("resources").filter_map do |entry|
  svc = entry.fetch("watch").fetch("service")
  loaded = Aws.constants.any? { |c| c.to_s.casecmp?(svc) }
  loaded ? nil : "#{entry.fetch('resource')} — add `require \"aws-sdk-#{svc}\"` to tests/unit/region_coverage_requires.rb"
end
REGIONS  = MANIFEST.fetch("regions")
OBSERVED = Hash.new { |h, k| h[k] = [] }

# Record the region of every stubbed call, then return a minimal valid shape.
# Guards against runaway pagination. With stub_responses and NO explicit payload
# the SDK fills every string member with a placeholder — including next_token —
# so a resource looping `break unless next_token` never terminates and the whole
# job hangs rather than failing. Supplying any payload hash makes unspecified
# members nil, which ends the loop; this cap catches the case where someone
# forgets, and turns an indefinite hang into a diagnosable failure.
#
# A hang is the worst outcome available here: it burns a runner, reports nothing,
# and looks like slowness rather than a defect.
CALL_CAP_PER_REGION = 50

# A named class rather than a raised string: callers can rescue this
# specifically, and the class name alone says what went wrong in a backtrace.
class RunawayPagination < StandardError; end

def recorder(key, payload = {})
  lambda do |ctx|
    OBSERVED[key] << ctx.client.config.region
    if OBSERVED[key].size > REGIONS.size * CALL_CAP_PER_REGION
      raise RunawayPagination,
            "runaway pagination on #{key}: over #{CALL_CAP_PER_REGION} calls per region. " \
            "The stub is almost certainly returning a placeholder next_token. Give this " \
            "entry a `payload:` in the manifest — any hash makes unspecified members nil " \
            "and ends the loop."
    end
    payload
  end
end

def install_stubs!(entries)
  Aws.config[:stub_responses] = true
  by_service = Hash.new { |h, k| h[k] = {} }
  by_service["ec2"][:describe_regions] = { regions: REGIONS.map { |r| { region_name: r } } }
  entries.each do |e|
    w = e.fetch("watch")
    svc = w.fetch("service")
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
end

def load_profile_libraries!
  # Underscore-prefixed helper libraries load first in InSpec's alphabetical
  # order and define the modules resources `include` (e.g. RegionEnumeration).
  # Evaluating a resource without them raises NameError, which would look like a
  # broken resource rather than a harness that loaded things out of order.
  Dir.glob("libraries/_*.rb").sort.each { |f| eval(File.read(f), TOPLEVEL_BINDING, f) } # rubocop:disable Security/Eval
end

install_stubs!(MANIFEST.fetch("resources"))
load_profile_libraries!

unless MISSING_GEMS.empty?
  warn "region coverage: #{MISSING_GEMS.size} resource(s) UNCHECKED — SDK gem not in the image:"
  MISSING_GEMS.each { |m| warn "  - #{m}" }
  warn "An unchecked resource is not a passing resource. Bake the gem or drop the entry deliberately."
  exit 1
end

failures = []
reported = []
unobservable = []
target_derived = []

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
    # A raise here is a LEAD, not a finding. This harness instantiates resources
    # outside InSpec's normal resource machinery, and something that machinery
    # supplies can be missing — which has already produced one false positive
    # against code that runs correctly in a real exec. So a resource explicitly
    # marked `unobservable` (with its reason) reports rather than fails; anything
    # else still fails loudly, because an unexplained raise must not be silent.
    if status == "unobservable"
      reason = e["reason"].to_s
      if reason.empty?
        failures << "#{name}: raised #{ex.class} and `unobservable` requires a `reason`"
      else
        unobservable << "#{name}: raised #{ex.class} — #{reason}"
        puts "  UNOBSERVABLE #{name} — raised #{ex.class}; #{reason}"
      end
    else
      failures << "#{name}: raised #{ex.class}: #{ex.message}"
    end
    next
  end

  seen   = OBSERVED[key].uniq.sort
  missed = REGIONS.sort - seen

  if missed.empty?
    puts "  PASS         #{name} — queried all #{REGIONS.size} regions"
  elsif status == "target_derived"
    # A third CORRECT pattern, distinct from both sweeping and being blind: the
    # region is resolved from the caller's own input — an ARN that names its
    # region, or the scan target itself (cis-rhel-9-baseline reads it from IMDS
    # on the host being scanned). Sweeping every region would be WRONG for these:
    # it would assess resources the caller did not ask about, possibly outside
    # the boundary. Requires a reason, and is NOT a defect.
    reason = e["reason"].to_s
    if reason.empty?
      failures << "#{name}: status `target_derived` requires a `reason`"
    else
      target_derived << "#{name}: #{reason}"
      puts "  TARGET-REGION #{name} — #{reason}"
    end
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
unless target_derived.empty?
  puts "#{target_derived.size} resource(s) resolve region from the caller's input (correct, not swept):"
  target_derived.each { |t| puts "  - #{t}" }
  puts
end
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
  puts "region coverage: OK (#{MANIFEST.fetch('resources').size} checked, #{reported.size} known-blind, #{unobservable.size} unobservable, #{target_derived.size} target-derived)"
  exit 0
end

warn "region coverage: #{failures.size} FAILURE(S)"
failures.each { |f| warn "  - #{f}" }
warn ""
warn "A resource marked `enforced` in region_coverage_manifest.yml must query every"
warn "region. If you intentionally made one single-region, say so in the manifest —"
warn "do not delete the entry."
exit 1
