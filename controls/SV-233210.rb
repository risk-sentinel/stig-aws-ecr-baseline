control 'SV-233210' do
 title 'Vulnerability scanning applications must implement privileged access
 authorization to all container platform components, containers, and container images
 for selected organization-defined vulnerability scanning activities.'
 desc 'In certain situations, the nature of the
 vulnerability scanning may be more intrusive, or the container platform component
 that is the subject of the scanning may contain highly sensitive information.
 Privileged access authorization to selected system components facilitates more
 thorough vulnerability scanning and protects the sensitive nature of such scanning.
 The vulnerability scanning application must utilize privileged access authorization
 for the scanning
 account.'
 desc 'check', 'Validate that scanning applications have privileged access to
 container platform components, containers, and container images to properly
 perform vulnerability scans. If privileged access is not given to the scanning
 application, this is a finding.'
 desc 'fix', 'Configure the vulnerability scanning application to
 have privileged access to the container platform components, containers, and
 container images.'
 impact 0.5
 tag check_id: 'C-36146r601117_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233210'
 tag rid: 'SV-233210r961563_rule'
 tag stig_id: 'SRG-APP-000414-CTR-001010'
 tag gtitle: 'SRG-APP-000414'
 tag fix_id: 'F-36114r601118_fix'
 tag 'documentable'
 tag cci: ['CCI-001067']
 tag nist: ['RA-5 (5)']
 tag ksi:  ['KSI-IAM-JIT', 'KSI-IAM-SNU']
 tag nist_r4: ['RA-5 (5)']
 tag implementation_status: 'implemented'
 tag fsbp: 'ECR.1'

 # Registry-layer: enhanced (Amazon Inspector) scanning provides the comprehensive,
 # privileged OS + language-package vulnerability scan of all image components, vs the
 # limited BASIC scan. Registry-wide setting; N/A when no ECR repositories are in scope.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 if input('require_enhanced_scanning', value: true)
 describe aws_ecr_registry_scanning(regions: scan_regions) do
 it { should be_enhanced }
 end
 else
 describe aws_ecr_registry_scanning(regions: scan_regions) do
 it { should be_configured }
 end
 end
end
