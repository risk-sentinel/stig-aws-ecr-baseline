control 'SV-233064' do
 title 'The container platform must be built from verified packages.'
 desc 'It is important to patch and upgrade the container
 platform when patches and upgrades are available. More important is to get these
 patches and upgrades from a known source. To validate the authenticity of any
 patches and upgrades before installation, the container platform must check that the
 files are digitally signed by sources approved by the
 organization.'
 desc 'check', 'Review the container platform configuration to verify it has been
 built from packages that are digitally signed by known and approved sources. If
 the container platform was built from packages that are not digitally signed or
 are from unknown or nonapproved sources, this is a finding.'
 desc 'fix', 'Rebuild the container platform from verified
 packages that are digitally signed by known and approved sources.'
 impact 0.5
 tag check_id: 'C-36000r981842_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233064'
 tag rid: 'SV-233064r981843_rule'
 tag stig_id: 'SRG-APP-000131-CTR-000280'
 tag gtitle: 'SRG-APP-000131'
 tag fix_id: 'F-35968r600680_fix'
 tag 'documentable'
 tag cci: ['CCI-003992']
 tag nist: ['CM-14']
 tag nist_r4: ['CM-5 (3)']
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
