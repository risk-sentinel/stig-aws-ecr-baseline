# encoding: UTF-8
#
# What a sigstore-bundle referrer holds.
#
# cosign 3 stores the signature and every attestation as referrers with one
# artifact type, application/vnd.dev.sigstore.bundle.v0.3+json. Only the
# bundle's annotations tell them apart:
#
#   dev.sigstore.bundle.content        dsse-envelope | message-signature
#   dev.sigstore.bundle.predicateType  https://sigstore.dev/cosign/sign/v1  <- signature
#                                      https://cyclonedx.org/bom            <- SBOM
#                                      anything else                        <- other attestation
#
# A bundle with neither annotation cannot be told apart and counts as a
# signature, which is how every bundle was counted before the annotations
# were read.

module ReferrerKind
  BUNDLE_MEDIA         = /sigstore\.bundle/i.freeze
  PREDICATE_ANNOTATION = "dev.sigstore.bundle.predicateType".freeze
  CONTENT_ANNOTATION   = "dev.sigstore.bundle.content".freeze
  SIGN_PREDICATE       = %r{\Ahttps://sigstore\.dev/cosign/sign/}i.freeze
  SBOM_PREDICATE       = /spdx|cyclonedx/i.freeze
  TYPE_FIELDS          = %i[artifact_media_type artifact_type media_type].freeze

  module_function

  # The non-empty artifact / media types a referrer reports.
  def types(ref)
    TYPE_FIELDS.filter_map do |m|
      v = ref.respond_to?(m) ? ref.public_send(m).to_s : ""
      v unless v.empty?
    end
  end

  def annotation(ref, key)
    ann = ref.respond_to?(:annotations) ? ref.annotations : nil
    ann.respond_to?(:[]) ? (ann[key] || ann[key.to_sym]).to_s : ""
  end

  def bundle?(ref)
    types(ref).any? { |t| t =~ BUNDLE_MEDIA }
  end

  def predicate_type(ref)
    annotation(ref, PREDICATE_ANNOTATION)
  end

  def bundle_signature?(ref)
    return false unless bundle?(ref)
    content = annotation(ref, CONTENT_ANNOTATION)
    predicate = predicate_type(ref)
    return true if content.casecmp("message-signature").zero?
    return predicate =~ SIGN_PREDICATE ? true : false unless predicate.empty?
    content.empty?
  end

  def bundle_sbom?(ref)
    bundle?(ref) && predicate_type(ref) =~ SBOM_PREDICATE ? true : false
  end

  # Types as reported, with a bundle's predicate type alongside it, so a gap
  # message says which attestations were present.
  def descriptions(ref)
    predicate = bundle?(ref) ? predicate_type(ref) : ""
    types(ref).map { |t| t =~ BUNDLE_MEDIA && !predicate.empty? ? "#{t} (#{predicate})" : t }
  end
end
