control 'SV-233026' do
 title 'Least privilege access and need-to-know must be required to access the container
 platform registry.'
 desc 'The container platform registry is used to store
 images and is the keeper of truth for trusted images within the platform. To
 guarantee the images integrity, access to the registry must be limited to those
 individuals who need to perform tasks to the images such as the update, creation, or
 deletion of images. Without this control access, images can be deleted that are in
 use by the container platform causing a denial of service (DoS), and images can be
 modified or introduced without going through the testing and validation process
 allowing for the intentional or unintentional introduction of containers with flaws
 and vulnerabilities. This requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review the container platform configuration to determine if least
 privilege and need-to-know access is being used for container platform registry
 access. If least privilege and need-to-know access is not being used for
 container platform registry access, this is a finding.'
 desc 'fix', 'Configure the container platform to use least
 privilege and need-to-know when granting access to the container platform registry.
 This fix ensures the proper roles and permissions are configured.'
 impact 0.5
 tag check_id: 'C-35962r601602_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233026'
 tag rid: 'SV-233026r1137638_rule'
 tag stig_id: 'SRG-APP-000033-CTR-000090'
 tag gtitle: 'SRG-APP-000033'
 tag fix_id: 'F-35930r1137616_fix'
 tag 'documentable'
 tag cci: ['CCI-000213']
 tag nist: ['AC-3']
 tag ksi:  ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
 tag nist_r4: ['AC-3']
 tag implementation_status: 'implemented'

 # Registry-layer ECR assertion (least-privilege registry access); account-wide, scoped via excluded_repositories.
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
