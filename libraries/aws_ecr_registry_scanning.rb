# encoding: UTF-8
#
# aws_ecr_registry_scanning — registry-level ECR scanning configuration
# (ecr:GetRegistryScanningConfiguration). BASIC = the built-in Clair-based scan;
# ENHANCED = Amazon Inspector deep OS + language-package scanning (the comprehensive,
# privileged scan). Registry-wide (one setting per account/region).
#
#   describe aws_ecr_registry_scanning do
#     it { should be_enhanced }
#   end

class AwsEcrRegistryScanning < AwsResourceBase
  include RegionScope
  name "aws_ecr_registry_scanning"
  desc "Registry-level ECR scanning configuration (basic vs enhanced/Inspector)."
  example "
    describe aws_ecr_registry_scanning do
      it { should be_enhanced }
    end
  "

  attr_reader :scan_type, :rules, :per_region

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    @rules = []
    @per_region = {}

    # Each region has its OWN registry and its own scanning configuration, so a
    # single call returns a perfectly valid config -- for one region. That is the
    # most misleading shape this defect takes: nothing about the result looks
    # wrong, and the control passes having described one registry out of several.
    @all_regions = region_scope_or_fail!(@aws, region_override)
    each_region_client(::Aws::ECR::Client) do |client, region|
      cfg = client.get_registry_scanning_configuration.scanning_configuration
      next if cfg.nil?
      @per_region[region] = { scan_type: cfg.scan_type, rules: Array(cfg.rules) }
      @rules.concat(Array(cfg.rules))
    end

    # Weakest posture across regions wins: a registry that is BASIC anywhere is
    # not ENHANCED everywhere, and reporting the strongest would hide the gap.
    types = @per_region.values.map { |v| v[:scan_type].to_s }.reject(&:empty?)
    @scan_type = types.include?("BASIC") ? "BASIC" : types.first
  end

  # Regions whose registry is not ENHANCED, so a gap names where it is.
  def regions_not_enhanced
    @per_region.reject { |_r, v| v[:scan_type].to_s == "ENHANCED" }.keys.sort
  end

  # ENHANCED = Amazon Inspector continuous/on-push deep scanning.
  def enhanced?
    @scan_type.to_s == "ENHANCED"
  end

  def configured?
    !@scan_type.to_s.empty?
  end

  # Scan frequencies declared in the registry rules (e.g. SCAN_ON_PUSH, CONTINUOUS_SCAN).
  def scan_frequencies
    @rules.map { |r| r.respond_to?(:scan_frequency) ? r.scan_frequency : nil }.compact
  end

  # ENHANCED alone does not mean images are rescanned. A rule may declare
  # SCAN_ON_PUSH or MANUAL, which is point-in-time: an image scanned clean at
  # push is never re-evaluated against CVEs disclosed afterwards, while the
  # registry still reports as "enhanced". CONTINUOUS_SCAN is the frequency that
  # makes the claim true.
  def continuous?
    scan_frequencies.map(&:to_s).include?("CONTINUOUS_SCAN")
  end

  # Repository names NOT matched by any rule's repository filter. A registry can
  # have enhanced scanning enabled while its rules cover only some repositories;
  # the uncovered ones are never scanned, and an unscanned repository produces
  # no findings — which reads as no problems.
  #
  # ECR repository filters are wildcard patterns. Note `myapp-prod-*` does NOT
  # match `myapp-prod` — a wildcard-boundary trap seen in testing, where a
  # scanner role could inspect only one repository out of six.
  def repositories_not_covered(names)
    patterns = @rules.flat_map do |r|
      next [] unless r.respond_to?(:repository_filters)
      Array(r.repository_filters).map { |f| f.respond_to?(:filter) ? f.filter.to_s : nil }
    end.compact
    return Array(names) if patterns.empty?
    Array(names).reject { |n| patterns.any? { |p| wildcard_match?(p, n) } }
  end

  def to_s
    "ECR Registry Scanning (#{@scan_type || 'unknown'})"
  end

  private

  # ECR filter wildcards: `*` matches zero or more characters, and the pattern
  # must match the WHOLE repository name.
  def wildcard_match?(pattern, name)
    re = Regexp.escape(pattern.to_s).gsub('\*', '.*')
    Regexp.new("\\A#{re}\\z").match?(name.to_s)
  end
end
