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
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image supply-chain (signed + SBOM) for #{name}" do
 subject { aws_ecr_repository(repository_name: name, regions: scan_regions).supply_chain_gaps }
 it { should be_empty }
 end
 end
end
