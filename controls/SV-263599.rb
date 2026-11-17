control 'SV-263599' do
 title 'The container platform must include only approved trust anchors in trust stores
 or certificate stores managed by the organization.'
 desc 'Public key infrastructure (PKI) certificates are
 certificates with visibility external to organizational systems and certificates
 related to the internal operations of systems, such as application-specific time
 services. In cryptographic systems with a hierarchical structure, a trust anchor is
 an authoritative source (i.e., a certificate authority) for which trust is assumed
 and not derived. A root certificate for a PKI system is an example of a trust
 anchor. A trust store or certificate store maintains a list of trusted root
 certificates.'
 desc 'check', 'Verify the container platform is configured to include only approved
 trust anchors in trust stores or certificate stores managed by the organization.
 If the container platform is not configured to include only approved trust
 anchors in trust stores or certificate stores managed by the organization, this
 is a finding.'
 desc 'fix', 'Configure the container platform to include only
 approved trust anchors in trust stores or certificate stores managed by the
 organization.'
 impact 0.5
 tag check_id: 'C-67499r982472_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-263599'
 tag rid: 'SV-263599r982473_rule'
 tag stig_id: 'SRG-APP-000910-CTR-000300'
 tag gtitle: 'SRG-APP-000910'
 tag fix_id: 'F-67407r981936_fix'
 tag 'documentable'
 tag cci: ['CCI-004909']
 tag nist: ['SC-17 b']
 tag nist_r4: ['SC-17']
 tag ksi:  ['KSI-SVC-ASM']
 tag implementation_status: 'implemented'
 tag fsbp: 'n/a'

 # Registry supply-chain: every in-scope image must be SIGNED (describe_image_signing_status)
 # AND carry an attached SBOM (list_image_referrers). Fail-closed: unsigned or no-SBOM == gap.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 # Signing trust from inputs, passed down: resources cannot read inputs.
 sig_opts = {
   signature_repository: input('signature_repository'),
   signing_keys: input('image_signing_keys'),
   trusted_signing_profiles: input('trusted_signing_profiles'),
 }
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image supply-chain (signed + SBOM) for #{name}" do
 subject { aws_ecr_repository(repository_name: name, regions: scan_regions, **sig_opts).supply_chain_gaps }
 it { should be_empty }
 end
 end

 # Approved source, separately from presence: a signature-shaped artifact is
 # not a signature from a key the organisation trusts.
 sig_keys, sig_key_errors = parse_signing_keys(sig_opts[:signing_keys])
 sig_verify = !sig_keys.empty? || !Array(sig_opts[:trusted_signing_profiles]).empty?
 verified_repo = {}
 describe 'Trusted image signing keys are readable' do
   subject { sig_key_errors }
   it { should be_empty }
 end
 repos.each do |name|
   if sig_verify
     describe "Image signatures from an approved source for #{name}" do
       subject { (verified_repo[name] ||= aws_ecr_repository(repository_name: name, regions: scan_regions, **sig_opts)).signature_verification_gaps }
       it { should be_empty }
     end
     describe "Image signature verification determinable for #{name} (no API errors)" do
       subject { (verified_repo[name] ||= aws_ecr_repository(repository_name: name, regions: scan_regions, **sig_opts)).signature_verification_undetermined }
       it { should be_empty }
     end
   else
     describe "Image signatures from an approved source for #{name}" do
       # HDF records the example description as the skip message, so the
       # reason lives there.
       reason = 'No image_signing_keys or trusted_signing_profiles configured: ' \
                'signatures were checked for presence only, not for an approved source.'
       it(reason) { skip reason }
     end
   end
 end
end
