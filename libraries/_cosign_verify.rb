# encoding: UTF-8
#
# Verification of key-based cosign signatures, without the cosign binary.
#
# A cosign signature is an OCI manifest whose layers are "simple signing"
# payloads. Each layer carries the base64 signature over its payload in the
# annotation below, and the payload names the image digest it signs:
#
#   { "critical": { "image": { "docker-manifest-digest": "sha256:..." }, ... } }
#
# A signature is accepted only when the payload hashes to the layer digest, the
# payload names the image being checked, and the signature verifies against one
# of the trusted public keys.

require "base64"
require "digest"
require "json"
require "openssl"

module CosignVerify
  SIGNATURE_ANNOTATION   = "dev.cosignproject.cosign/signature".freeze
  CERTIFICATE_ANNOTATION = "dev.sigstore.cosign/certificate".freeze
  MANIFEST_MEDIA_TYPES = %w[
    application/vnd.oci.image.manifest.v1+json
    application/vnd.docker.distribution.manifest.v2+json
  ].freeze

  module_function

  # Parse PEM public keys. Returns [keys, errors]; a key that does not parse is
  # reported, never silently dropped.
  def parse_keys(pems)
    keys = []
    errors = []
    Array(pems).each_with_index do |pem, i|
      text = pem.to_s.strip
      next if text.empty?
      keys << OpenSSL::PKey.read(text)
    rescue OpenSSL::PKey::PKeyError, ArgumentError => e
      errors << "image_signing_keys[#{i}]: not a readable public key (#{e.class})"
    end
    [keys, errors]
  end

  # The signature layers of a cosign signature manifest (JSON text):
  # [{ digest:, signature:, keyless: }].
  def signature_layers(manifest_json)
    doc = JSON.parse(manifest_json.to_s)
    Array(doc["layers"]).filter_map do |l|
      ann = l["annotations"] || {}
      sig = ann[SIGNATURE_ANNOTATION].to_s
      next if sig.empty?
      { digest: l["digest"].to_s, signature: sig, keyless: !ann[CERTIFICATE_ANNOTATION].to_s.empty? }
    end
  rescue JSON::ParserError
    []
  end

  # nil when the payload verifies for image_digest under one of keys; otherwise
  # the reason it does not.
  def verify(payload, layer_digest, signature_b64, keys, image_digest)
    actual = "sha256:#{Digest::SHA256.hexdigest(payload.to_s)}"
    return "payload does not match its layer digest" unless actual == layer_digest.to_s

    signed = begin
      JSON.parse(payload.to_s).dig("critical", "image", "docker-manifest-digest").to_s
    rescue JSON::ParserError
      ""
    end
    return "payload is not a cosign signing payload" if signed.empty?
    return "signature is for #{signed[0, 19]}…, not this image" unless signed == image_digest.to_s

    sig = Base64.decode64(signature_b64.to_s)
    return nil if Array(keys).any? { |k| key_verifies?(k, sig, payload.to_s) }
    "signature does not verify against any trusted key"
  end

  def key_verifies?(key, sig, data)
    digest = key.oid == "ED25519" ? nil : "SHA256"
    key.verify(digest, sig, data)
  rescue OpenSSL::PKey::PKeyError
    false
  end
end

# Control bodies cannot see library constants, so they parse the
# image_signing_keys input through this helper. Read it into a local in the
# control body; `it` blocks run where the method is absent.
module CosignVerifyHelpers
  def parse_signing_keys(pems)
    CosignVerify.parse_keys(pems)
  end
end

::Inspec::Rule.include(CosignVerifyHelpers)
