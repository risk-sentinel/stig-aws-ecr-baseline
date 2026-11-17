control 'SV-233028' do
 title 'Least privilege access and need-to-know must be required to access the container
 platform keystore.'
 desc 'The container platform keystore is used to store
 access keys and tokens for trusted access to and from the container platform. The
 keystore gives the container platform a method to store the confidential data in a
 secure way and to encrypt the data when at rest. If this data is not protected
 through access controls, it can be used to access trusted sources as the container
 platform breaking the trusted relationship. To circumvent unauthorized access to the
 keystore, the container platform must have access controls in place to only allow
 those individuals with keystore duties. This requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review the container platform to determine if only those individuals
 with keystore duties have access to the container platform keystore. If users
 have access to the container platform keystore that do not have keystore duties,
 this is a finding.'
 desc 'fix', 'Configure the container platform to use least
 privilege and need-to-know when granting access to the container keystore. This fix
 ensures the proper roles and permissions are configured.'
 impact 0.5
 tag check_id: 'C-35964r600571_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233028'
 tag rid: 'SV-233028r1137640_rule'
 tag stig_id: 'SRG-APP-000033-CTR-000100'
 tag gtitle: 'SRG-APP-000033'
 tag fix_id: 'F-35932r1137620_fix'
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
