control 'SV-233066' do
 title 'The container platform must limit privileges to the container platform registry.'
 desc 'To control what is instantiated within the container
 platform, it is important to control access to the registry. Without this control,
 container images can be introduced and instantiated by accident or on container
 platform startup. Without control of the registry, security measures put in place
 for the runtime can be bypassed meaning the controls of approval and testing are
 also bypassed. Only those individuals and roles approved by the organization can
 have access to the container platform
 registry.'
 desc 'check', 'Review the container platform registry configuration to determine if
 the level of access to the registry is controlled through user privileges.
 Attempt to perform registry operations to determine if the privileges are
 enforced. If the container platform registry is not limited through user
 privileges or the user privileges are not enforced, this is a finding.'
 desc 'fix', 'Configure the container platform to use and enforce
 user privileges when accessing the container platform registry.'
 impact 0.5
 tag check_id: 'C-36002r601872_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233066'
 tag rid: 'SV-233066r960960_rule'
 tag stig_id: 'SRG-APP-000133-CTR-000290'
 tag gtitle: 'SRG-APP-000133'
 tag fix_id: 'F-35970r600686_fix'
 tag 'documentable'
 tag cci: ['CCI-001499']
 tag nist: ['CM-5 (6)']
 tag nist_r4: ['CM-5 (6)']
 tag implementation_status: 'implemented'

 # Registry-layer ECR assertion (limit registry privileges); account-wide, scoped via excluded_repositories.
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
