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
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image supply-chain (signed + SBOM) for #{name}" do
 subject { aws_ecr_repository(repository_name: name).supply_chain_gaps }
 it { should be_empty }
 end
 end
end
