#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Contract test for how sigstore-bundle referrers (cosign 3) count.
#
# The signature and every attestation share one artifact type; only the
# bundle's predicateType annotation says which is which. The fixtures are the
# three referrers a cosign 3 release actually carries: an SBOM, a vulnerability
# attestation and the signature.
#
# Both directions are checked through the resource's own methods against a
# stubbed ListImageReferrers: an SBOM bundle must count as an SBOM, and an
# attestation must NOT count as a signature.
#
# Run: ruby tests/unit/referrer_kind_test.rb   (needs `cinc-auditor vendor` first)

STUB_REGION     = "us-east-1"
STUB_CREDENTIAL = "stubbed"
ENV["AWS_REGION"]            ||= STUB_REGION
ENV["AWS_ACCESS_KEY_ID"]     ||= STUB_CREDENTIAL
ENV["AWS_SECRET_ACCESS_KEY"] ||= STUB_CREDENTIAL

require "inspec"
require "aws-sdk-core"
require "aws-sdk-ecr"

VENDOR = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
abort "FATAL: no vendored inspec-aws — run `cinc-auditor vendor . --overwrite` first." if VENDOR.nil?
$LOAD_PATH.unshift(VENDOR)
require "aws_backend"
%w[libraries/_region_scope_helpers.rb libraries/_cosign_verify.rb libraries/_referrer_kind.rb libraries/aws_ecr_repository.rb].each do |f|
  eval(File.read(f), TOPLEVEL_BINDING, f) # rubocop:disable Security/Eval
end

BUNDLE   = "application/vnd.dev.sigstore.bundle.v0.3+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
SIGN     = "https://sigstore.dev/cosign/sign/v1"
SBOM     = "https://cyclonedx.org/bom"
SPDX     = "https://spdx.dev/Document"
VULN     = "https://cosign.sigstore.dev/attestation/vuln/v1"
SUBJECT  = "sha256:#{'a' * 64}"

def bundle(predicate: nil, content: "dsse-envelope")
  ann = {}
  ann["dev.sigstore.bundle.content"] = content if content
  ann["dev.sigstore.bundle.predicateType"] = predicate if predicate
  { digest: "sha256:#{rand(16**64).to_s(16).rjust(64, '0')}", media_type: MANIFEST,
    artifact_type: BUNDLE, size: 1, annotations: ann }
end

FAILURES = []

def check(desc, actual, expected)
  if actual == expected
    puts "  PASS  #{desc}"
  else
    puts "  FAIL  #{desc}\n        expected #{expected.inspect}\n        got      #{actual.inspect}"
    FAILURES << desc
  end
end

# The resource's real methods, with only the ECR client and repository name set.
def repo_with(referrers)
  client = Aws::ECR::Client.new(stub_responses: { list_image_referrers: { referrers: referrers } })
  repo = AwsEcrRepository.allocate
  repo.instance_variable_set(:@client, client)
  repo.instance_variable_set(:@repository_name, "stub")
  repo
end

def verdict(referrers)
  repo = repo_with(referrers)
  { signed: repo.send(:referrer_signed?, SUBJECT), sbom: repo.send(:referrer_sbom?, SUBJECT) }
end

def ref(hash)
  Aws::ECR::Types::ImageReferrer.new(**hash)
end

puts "release as published (SBOM + vuln attestation + signature)"
check "signed, with an SBOM",
      verdict([bundle(predicate: SBOM), bundle(predicate: VULN), bundle(predicate: SIGN)]),
      { signed: true, sbom: true }

puts "attestations without a signature"
check "SBOM + vuln attestation: an SBOM, but NOT signed",
      verdict([bundle(predicate: SBOM), bundle(predicate: VULN)]), { signed: false, sbom: true }
check "vuln attestation only: neither",
      verdict([bundle(predicate: VULN)]), { signed: false, sbom: false }
check "SPDX SBOM counts as an SBOM",
      verdict([bundle(predicate: SPDX)]), { signed: false, sbom: true }
check "DSSE bundle with no predicate type: not a signature",
      verdict([bundle(predicate: nil)]), { signed: false, sbom: false }

puts "signatures"
check "signature only: signed, no SBOM",
      verdict([bundle(predicate: SIGN)]), { signed: true, sbom: false }
check "message-signature bundle: signed",
      verdict([bundle(predicate: nil, content: "message-signature")]), { signed: true, sbom: false }
check "bundle with no annotations at all: still counted as signed",
      verdict([bundle(predicate: nil, content: nil)]), { signed: true, sbom: false }
check "no referrers: neither",
      verdict([]), { signed: false, sbom: false }

puts "other formats are unchanged"
check "cosign .sig referrer is a signature",
      verdict([{ digest: SUBJECT, media_type: MANIFEST, artifact_type: "application/vnd.dev.cosign.artifact.sig.v1+json", size: 1 }]),
      { signed: true, sbom: false }
check "Notation signature is a signature",
      verdict([{ digest: SUBJECT, media_type: MANIFEST, artifact_type: "application/vnd.cncf.notary.signature", size: 1 }]),
      { signed: true, sbom: false }

puts "gap text names the predicate"
check "descriptions carry the bundle's predicate type",
      ReferrerKind.descriptions(ref(bundle(predicate: SBOM))),
      ["#{BUNDLE} (#{SBOM})", MANIFEST]
check "the SDK's ImageReferrer carries annotations",
      ReferrerKind.bundle_sbom?(ref(bundle(predicate: SBOM))), true

if FAILURES.empty?
  puts "\nAll referrer-kind checks passed."
else
  puts "\n#{FAILURES.size} referrer-kind check(s) FAILED."
  exit 1
end
