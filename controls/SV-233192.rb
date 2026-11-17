control 'SV-233192' do
 title 'The container platform registry must employ a deny-all, permit-by-exception
 (whitelist) policy to allow only authorized container images in the container
 platform.'
 desc 'Controlling the sources where container images can be
 pulled from allows the organization to define what software can be run within the
 container platform. Allowing any container image to be introduced and instantiated
 within the container platform may introduce malicious code and vulnerabilities to
 the platform and the hosting system. The container platform registry must deny all
 container images except for those signed by organizational-approved
 sources.'
 desc 'check', 'Review documentation and configuration settings to identify if the
 container platform whitelisting specifies which container platform components
 are allowed to execute. Check for the existence of policy settings or policy
 files that can be configured to restrict container platform component execution.
 Demonstrate how the program execution is restricted. Look for a deny-all,
 permit-by-exception policy of restriction. Some methods for restricting
 execution include but are not limited to the use of custom capabilities built
 into the application or Software Restriction Policies, Application Security
 Manager, or Role-Based Access Controls (RBAC). If container platform
 whitelisting is not utilized or does not follow a deny-all, permit-by-exception
 (whitelist) policy, this is a finding.'
 desc 'fix', 'Configure the container platform to utilize a
 deny-all, permit-by-exception policy when allowing the execution of authorized
 software.'
 impact 0.5
 tag check_id: 'C-36128r601797_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233192'
 tag rid: 'SV-233192r961479_rule'
 tag stig_id: 'SRG-APP-000386-CTR-000920'
 tag gtitle: 'SRG-APP-000386'
 tag fix_id: 'F-36096r601064_fix'
 tag 'documentable'
 tag cci: ['CCI-001774']
 tag nist: ['CM-7 (5) (b)']
 tag ksi:  ['KSI-IAM-JIT', 'KSI-PIY-GIV']
 tag nist_r4: ['CM-7 (5) (b)']
 tag implementation_status: 'implemented'

 # Registry-layer ECR assertion (deny-all / permit-by-exception); account-wide, scoped via excluded_repositories.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe aws_ecr_repository(repository_name: name, regions: scan_regions) do
 it { should_not be_policy_allows_external }
 end
 end
end
