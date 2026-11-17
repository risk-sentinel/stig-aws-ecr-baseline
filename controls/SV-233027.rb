control 'SV-233027' do
 title 'Least privilege access and need-to-know must be required to access the container
 platform runtime.'
 desc 'The container platform runtime is used to instantiate
 containers. If this process is accessed by those persons who are not authorized,
 those containers offering services can be brought to a denial-of-service (DoS)
 situation, disabling a large number of services with a small change to the container
 platform. To limit this threat, it is important to limit access to the runtime to
 only those individuals with runtime duties. This requirement also applies to Zero
 Trust
 initiatives.'
 desc 'check', 'Review the container platform to determine if only those individuals
 with runtime duties have access to the container platform runtime. If users have
 access to the container platform runtime that do not have runtime duties, this
 is a finding.'
 desc 'fix', 'Configure the container platform to use least
 privilege and need-to-know when granting access to the container runtime. This fix
 ensures the proper roles and permissions are configured.'
 impact 0.5
 tag check_id: 'C-35963r600568_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233027'
 tag rid: 'SV-233027r1137639_rule'
 tag stig_id: 'SRG-APP-000033-CTR-000095'
 tag gtitle: 'SRG-APP-000033'
 tag fix_id: 'F-35931r1137618_fix'
 tag 'documentable'
 tag cci: ['CCI-000213']
 tag nist: ['AC-3']
 tag ksi:  ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
 tag nist_r4: ['AC-3']
 tag implementation_status: 'implemented'

 # Least-privilege access to the registry: no public/cross-account principal.
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
