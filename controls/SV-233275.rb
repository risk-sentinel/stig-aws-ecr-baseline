control 'SV-233275' do
 title 'The container platform must continuously scan components, containers, and images
 for vulnerabilities.'
 desc 'Finding vulnerabilities quickly within the container
 platform and within containers deployed within the platform is important to keep the
 overall platform secure. When a vulnerability within a component or container is
 unknown or allowed to remain unpatched, other containers and customers within the
 platform become vulnerability. The vulnerability can lead to the loss of application
 data, organizational infrastructure data, and denial of service (DoS) to hosted
 applications. Vulnerability scanning can be performed by the container platform or
 by external
 applications.'
 desc 'check', 'Review the container platform to validate continuous vulnerability
 scans of components, containers, and container images are being performed. If
 continuous vulnerability scans are not being performed, this is a finding.'
 desc 'fix', 'Implement continuous vulnerability scans of
 container platform components, containers, and container images either by the
 container platform or from external vulnerability scanning applications.'
 impact 0.5
 tag check_id: 'C-36211r601312_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233275'
 tag rid: 'SV-233275r961863_rule'
 tag stig_id: 'SRG-APP-000516-CTR-001335'
 tag gtitle: 'SRG-APP-000516'
 tag fix_id: 'F-36179r601313_fix'
 tag 'documentable'
 tag cci: ['CCI-000366']
 tag nist: ['CM-6 b']
 tag ksi:  ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
 tag nist_r4: ['CM-6 b']
 tag implementation_status: 'implemented'
 tag fsbp: 'ECR.1'

 # Registry-layer ECR assertion (continuous image scanning); account-wide, scoped via excluded_repositories.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe aws_ecr_repository(repository_name: name, regions: scan_regions) do
 it { should be_scan_on_push }
 end
 end

 # scan-on-push alone does NOT satisfy this control's own requirement. It is a
 # point-in-time scan: an image scanned clean at push is never re-evaluated
 # against CVEs disclosed afterwards, even while it is still deployed. The
 # control title says "continuously scan"; only CONTINUOUS_SCAN delivers that.
 describe aws_ecr_registry_scanning(regions: scan_regions) do
 it { should be_continuous }
 end

 # Enhanced scanning can be enabled while its rules cover only some
 # repositories. An uncovered repository is never scanned, and an unscanned
 # repository produces no findings — indistinguishable from a clean one.
 # Note ECR filter wildcards are anchored: `foo-*` does not match `foo`.
 uncovered = aws_ecr_registry_scanning(regions: scan_regions).repositories_not_covered(repos)
 describe "ECR scanning rule coverage of in-scope repositories (#{repos.length} in scope)" do
 subject { uncovered }
 it { should be_empty }
 end
end
