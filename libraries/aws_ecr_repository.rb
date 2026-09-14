# encoding: UTF-8
#
# aws_ecr_repository — posture of a single ECR repository: scan-on-push, image-tag
# mutability, encryption (KMS vs AES256), repository policy (parsed for public /
# cross-account access), and lifecycle-policy presence.
#
#   describe aws_ecr_repository(repository_name: 'app') do
#     it { should be_scan_on_push }
#     its('image_tag_mutability') { should cmp 'IMMUTABLE' }
#   end
#
# RepositoryPolicyNotFound / LifecyclePolicyNotFound are EXPECTED when unset and are
# rescued (not treated as resource errors) so the policy/lifecycle predicates report
# "absent" rather than failing the whole resource.

require "json"
require "set"   # Enumerable#to_set — autoloaded in Ruby 3.4, explicit here so the
                # resource does not depend on the runtime's autoload behaviour.

class AwsEcrRepository < AwsResourceBase
  include RegionScope
  name "aws_ecr_repository"
  desc "Configuration + policy posture of a single ECR repository."
  example "
    describe aws_ecr_repository(repository_name: 'app') do
      it { should be_immutable }
    end
  "

  attr_reader :repository_name, :repository_arn, :registry_id,
              :image_tag_mutability, :encryption_type, :kms_key,
              :policy_text, :lifecycle_policy_text

  def initialize(opts = {})
    opts = { repository_name: opts } if opts.is_a?(String)
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    explicit_region = opts.delete(:region)
    super(opts)
    validate_parameters(required: %i[repository_name])
    @repository_name = opts[:repository_name]
    @exists = false
    @found_in_regions = []

    # A repository name is only unique WITHIN a region -- two regions can hold
    # one of the same name. So rather than assume a region, find which region(s)
    # actually hold it, and record that. An explicit `region:` (or an ARN, via
    # client_region_for) short-circuits the search when the caller already knows.
    #
    # Silently picking one region would be the original defect in miniature:
    # the control would report on a repository that may not be the one meant.
    targeted = client_region_for(@repository_name, explicit_region)
    @all_regions = targeted ? [targeted] : region_scope_or_fail!(@aws, region_override)

    each_region_client(::Aws::ECR::Client) do |c, region|
      probe = c.describe_repositories(repository_names: [@repository_name]) rescue nil
      next if probe.nil? || probe.repositories.to_a.empty?
      @found_in_regions << region
      @client ||= c
      @region ||= region
    end
    @client ||= @client

    catch_aws_errors do
      resp = @client.describe_repositories(repository_names: [@repository_name])
      repo = resp.repositories.first
      next if repo.nil?

      @exists               = true
      @repository_arn       = repo.repository_arn
      @registry_id          = repo.registry_id
      @image_tag_mutability = repo.image_tag_mutability
      @scan_on_push         = repo.image_scanning_configuration&.scan_on_push == true
      enc                   = repo.encryption_configuration
      @encryption_type      = enc&.encryption_type
      @kms_key              = enc&.kms_key

      @policy_text = begin
        @client.get_repository_policy(repository_name: @repository_name).policy_text
      rescue Aws::ECR::Errors::RepositoryPolicyNotFoundException
        nil
      end

      @lifecycle_policy_text = begin
        @client.get_lifecycle_policy(repository_name: @repository_name).lifecycle_policy_text
      rescue Aws::ECR::Errors::LifecyclePolicyNotFoundException
        nil
      end
    end
  end

  # The region this repository was read from, and every region it was found in.
  # More than one means the NAME is ambiguous across regions -- a control
  # asserting on it should say which region it meant.
  attr_reader :region, :found_in_regions

  def ambiguous_across_regions?
    @found_in_regions.size > 1
  end

  def exists?
    @exists == true
  end

  def scan_on_push?
    @scan_on_push == true
  end

  def immutable?
    @image_tag_mutability.to_s == "IMMUTABLE"
  end

  def kms_encrypted?
    @encryption_type.to_s == "KMS"
  end

  def has_repository_policy?
    !@policy_text.to_s.empty?
  end

  def has_lifecycle_policy?
    !@lifecycle_policy_text.to_s.empty?
  end

  # True if the repository policy grants access to a principal outside this account
  # (a public "*" principal, or a cross-account IAM ARN). Used by the deny-all /
  # permit-by-exception + least-privilege registry controls.
  def policy_allows_external?
    return false if @policy_text.to_s.empty?
    doc = (JSON.parse(@policy_text) rescue nil)
    return false if doc.nil?
    Array(doc["Statement"]).any? do |st|
      next false unless st["Effect"] == "Allow"
      pr = st["Principal"]
      principals = pr.is_a?(Hash) ? Array(pr["AWS"]) : Array(pr)
      principals.map(&:to_s).any? do |p|
        p == "*" || (p =~ /arn:aws[^:]*:iam::(\d{12}):/ && Regexp.last_match(1) != @registry_id.to_s)
      end
    end
  end

  # Lazily-fetched image inventory (DescribeImages, paginated): per-image digest, tags,
  # scan status, and finding-severity counts. Fetched only when a control needs it.
  def images
    return @images if defined?(@images)
    @images = []
    @all_tags = []
    catch_aws_errors do
      next_token = nil
      loop do
        resp = @client.describe_images(repository_name: @repository_name, next_token: next_token, max_results: 100)
        Array(resp.image_details).each do |d|
          # Every imageDetail's tags are collected FIRST — cosign pushes
          # signatures and attestations as separate TAGGED artifacts in this
          # same repository, and those tags are how a signature is detected
          # (see image_signed?). Skipping them here would discard the evidence.
          @all_tags.concat(Array(d.image_tags))

          # ...but a signature is not an image. artifactMediaType is non-null
          # ONLY for OCI artifacts that are not images (cosign signatures,
          # attestations, SBOMs). Including them made every signature report as
          # an unsigned image, and counted each as unscanned in the scan gate.
          next unless d.respond_to?(:artifact_media_type) && d.artifact_media_type.to_s.empty?

          summary = d.image_scan_findings_summary
          @images << {
            digest:          d.image_digest,
            tags:            Array(d.image_tags),
            scan_status:     d.image_scan_status&.status.to_s,
            severity_counts: (summary && summary.finding_severity_counts) || {},
          }
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
    @images
  end

  # Every tag in the repository, including those on non-image artifacts.
  def all_tags
    images # populates @all_tags as a side effect of the single DescribeImages pass
    @all_tags || []
  end

  # Image digests/tags that violate the scan gate: fail-closed — an image whose scan is
  # not COMPLETE counts as a violation (unscanned == unproven == non-compliant), as does
  # any image carrying findings above the tolerated severity ceiling.
  def scan_gate_violations(ceiling)
    rank = %w[INFORMATIONAL LOW MEDIUM HIGH CRITICAL]
    idx  = rank.index(ceiling.to_s.upcase) || rank.index("HIGH")
    disallowed = rank[(idx + 1)..] || []
    images.select do |im|
      next true unless im[:scan_status] == "COMPLETE" # fail-closed: unscanned == violation
      counts = im[:severity_counts] || {}
      disallowed.sum { |s| counts[s].to_i + counts[s.to_sym].to_i } > 0
    end.map { |im| im[:tags].first || im[:digest] }
  end

  # ---------------------------------------------------------------------------
  # Media-type classification.
  #
  # cosign 3.x (OCI 1.1) distinguishes signature from attestation ONLY by the
  # `.sig` / `.att` infix:
  #
  #   application/vnd.dev.cosign.artifact.sig.v1+json   <- signature
  #   application/vnd.dev.cosign.artifact.att.v1+json   <- attestation (SBOM,
  #                                                        provenance, …)
  #
  # A pattern matching bare `cosign` therefore matches BOTH, and an SBOM
  # attestation silently satisfies a signature check while the SBOM check —
  # looking for `cyclonedx` — finds nothing, because the predicate type lives
  # inside the DSSE payload, not in the artifact media type. That combination
  # produced "signed + no-SBOM" for images that are in fact both signed AND
  # SBOM-attested. Match the infix explicitly, never bare `cosign`.
  # ---------------------------------------------------------------------------

  SIGNATURE_MEDIA = %r{
    cosign\.artifact\.sig|
    simplesigning|
    notary\.signature|notation\.signature|
    sigstore\.bundle
  }xi.freeze

  # Attestation envelopes. The predicate (CycloneDX / SPDX / SLSA provenance) is
  # inside the signed payload and is NOT visible in the referrer metadata, so
  # this cannot by itself prove the attestation is an SBOM — see
  # attestation_kinds_undetermined below, which reports that honestly rather
  # than guessing in either direction.
  ATTESTATION_MEDIA = %r{
    cosign\.artifact\.att|
    dsse\.envelope|
    in-toto
  }xi.freeze

  # Predicate types that ARE identifiable from referrer metadata, when the
  # registry surfaces the predicate as the artifactType rather than an envelope.
  SBOM_MEDIA = /spdx|cyclonedx|\bsbom\b/i.freeze

  # Images missing a signature and/or an SBOM referrer (supply-chain gaps). Fail-closed:
  # an unsigned image, or one without an attached SBOM, is a gap. Returns labels.
  def supply_chain_gaps
    images.map do |im|
      miss = []
      miss << "unsigned" unless image_signed?(im[:digest])
      miss << "no-SBOM"  unless image_has_sbom?(im[:digest])
      next nil if miss.empty?
      # Self-diagnosing: list the referrers that WERE present. A gap reporting
      # what it saw can be acted on; a bare "no-SBOM" is indistinguishable from
      # a media-type pattern that failed to match, which is exactly how two
      # earlier versions of this check were wrong.
      seen = observed_referrer_types(im[:digest])
      saw = seen.empty? ? "no referrers found" : "referrers seen: #{seen.join(', ')}"
      "#{im[:tags].first || im[:digest][0, 16]}: #{miss.join('+')} [#{saw}]"
    end.compact
  end

  # Images whose supply-chain state could NOT be determined — an API error, a
  # denied permission, a throttle. Deliberately separate from supply_chain_gaps:
  # "cannot determine" is not "non-compliant". Folding the two together
  # made an IAM denial indistinguishable from an unsigned image, so the control
  # was untrustworthy in both directions.
  def supply_chain_undetermined
    images.map do |im|
      reasons = []
      reasons << "signing: #{[@referrer_error, @signing_error].compact.join('/')}" if signing_undetermined?(im[:digest])
      reasons << "sbom: #{@sbom_error}"                                            if sbom_undetermined?(im[:digest])
      reasons.empty? ? nil : "#{im[:tags].first || im[:digest][0, 16]}: #{reasons.join('; ')}"
    end.compact
  end

  # ---- reverse direction: artifact -> subject -------------------------------
  # Forward resolution (image -> its referrers) answers "is this image signed".
  # It cannot explain an artifact that belongs to something else. Reverse
  # resolution maps every cosign-style tag back to the digest it describes, so
  # a signature for a SUPERSEDED image, or for a CHILD manifest inside a
  # multi-arch Image Index, is reported rather than silently ignored.

  # subject digest => [kinds] for every sha256-<digest>.<kind> tag in the repo.
  def signature_subjects
    all_tags.each_with_object({}) do |t, acc|
      m = /\Asha256-(?<d>[0-9a-f]{64})\.(?<kind>sig|att|sbom)\z/.match(t.to_s)
      next unless m
      (acc["sha256:#{m[:d]}"] ||= []) << m[:kind]
    end
  end

  # Supply-chain artifacts whose subject is NOT a current image in this
  # repository. Either the image was replaced and its signature left behind, or
  # the subject is a child manifest of an Image Index — both are worth seeing,
  # and neither is visible from the forward direction alone.
  def orphan_supply_chain_artifacts
    known = images.map { |im| im[:digest] }.to_set
    signature_subjects.reject { |subject, _| known.include?(subject) }
                      .map { |subject, kinds| "#{subject[0, 19]}…: #{kinds.sort.join('+')} (no current image with this digest)" }
  end

  # Referrer artifact types actually observed, per image. Emitted alongside a
  # gap so the finding explains itself: a "no-SBOM" that lists the referrers it
  # DID see is diagnosable, one that lists nothing is a guess. Two rounds of
  # media-type patterns were wrong before this existed.
  def observed_referrer_types(digest)
    referrers_for(digest).flat_map do |r|
      %i[artifact_media_type artifact_type media_type].filter_map do |m|
        r.public_send(m).to_s if r.respond_to?(m) && !r.public_send(m).to_s.empty?
      end
    end.uniq
  rescue StandardError
    []
  end

  def to_s
    "ECR Repository #{@repository_name}"
  end

  private

  # ---- cosign tag scheme ----------------------------------------------------
  # cosign's pre-OCI-1.1 default: the signature for sha256:X is a separate
  # artifact tagged `sha256-X.sig` in the SAME repository. Resolved from the
  # DescribeImages pass already made, so it costs no API call and needs no
  # additional IAM grant.

  def cosign_tag_for(digest, suffix)
    "sha256-#{digest.to_s.delete_prefix('sha256:')}.#{suffix}"
  end

  def cosign_signed?(digest)
    all_tags.include?(cosign_tag_for(digest, "sig"))
  end

  def cosign_attested?(digest)
    %w[att sbom].any? { |s| all_tags.include?(cosign_tag_for(digest, s)) }
  end

  # ---- signature detection --------------------------------------------------
  # Three unrelated mechanisms; any one counts as signed. Ordered cheapest-first.

  def image_signed?(digest)
    return true if cosign_signed?(digest)     # tags — no API call
    return true if referrer_signed?(digest)   # OCI 1.1 referrers
    native_signed?(digest)                    # AWS Signer / Notation
  end

  def referrer_signed?(digest)
    @referrer_error = nil
    referrer_matches?(referrers_for(digest), SIGNATURE_MEDIA)
  rescue StandardError => e
    @referrer_error = e.class.name
    false
  end

  def native_signed?(digest)
    @signing_error = nil
    !Array(@client.describe_image_signing_status(
      repository_name: @repository_name, image_id: { image_digest: digest }
    ).signing_statuses).empty?
  rescue StandardError => e
    @signing_error = e.class.name
    false
  end

  # True only when NO signature was found by any mechanism AND at least one
  # mechanism that makes an API call errored — the answer is unknown, not "no".
  def signing_undetermined?(digest)
    return false if cosign_signed?(digest)
    referrer_signed?(digest)
    referrer_err = @referrer_error
    native_signed?(digest)
    !(referrer_err.nil? && @signing_error.nil?)
  end

  # ---- SBOM detection -------------------------------------------------------

  def image_has_sbom?(digest)
    return true if cosign_attested?(digest)   # tags — no API call
    referrer_sbom?(digest)
  end

  def referrer_sbom?(digest)
    @sbom_error = nil
    refs = referrers_for(digest)
    # An SBOM predicate named outright, OR a cosign attestation envelope. The
    # envelope's predicate type lives inside the signed payload and is NOT
    # visible in referrer metadata, so an attestation counts as evidence here.
    # Proving it is specifically an SBOM would mean fetching the payload.
    referrer_matches?(refs, SBOM_MEDIA) || referrer_matches?(refs, ATTESTATION_MEDIA)
  rescue StandardError => e
    @sbom_error = e.class.name
    false
  end

  def sbom_undetermined?(digest)
    return false if cosign_attested?(digest)
    referrer_sbom?(digest)
    !@sbom_error.nil?
  end

  # ---- referrer plumbing ----------------------------------------------------
  # Pagination and matching in one place so the signature and SBOM paths cannot
  # drift apart.

  def referrers_for(digest)
    refs = []
    token = nil
    loop do
      resp = @client.list_image_referrers(
        repository_name: @repository_name, subject_id: { image_digest: digest }, next_token: token
      )
      refs.concat(Array(resp.referrers))
      token = resp.next_token
      break if token.nil? || token.to_s.empty?
    end
    refs
  end

  def referrer_matches?(refs, pattern)
    refs.any? do |r|
      %i[artifact_media_type artifact_type media_type].any? do |m|
        r.respond_to?(m) && r.public_send(m).to_s =~ pattern
      end
    end
  end
end
