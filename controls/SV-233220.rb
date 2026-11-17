control 'SV-233220' do
 title 'The container platform keystore must implement encryption to prevent unauthorized
 disclosure of information at rest within the container platform.'
 desc 'Container platform keystore is used for container
 deployments for persistent storage of all its REST API objects. These objects are
 sensitive in nature and should be encrypted at rest to avoid any unauthorized
 disclosure. Selection of a cryptographic mechanism is based on the need to protect
 the confidentiality of organizational information. The strength of mechanism is
 commensurate with the security category and/or classification of the
 information.'
 desc 'check', 'Review container platform keystore documentation and configuration to
 verify encryption levels meet the information sensitivity level. If the
 container platform keystore encryption configuration does not meet system
 requirements, this is a finding.'
 desc 'fix', 'Configure the container platform keystore
 encryption to maintain the confidentiality and integrity of information for
 applicable sensitivity level.'
 impact 0.7
 tag check_id: 'C-36156r601147_chk'
 tag severity: 'high'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233220'
 tag rid: 'SV-233220r1050650_rule'
 tag stig_id: 'SRG-APP-000429-CTR-001060'
 tag gtitle: 'SRG-APP-000429'
 tag fix_id: 'F-36124r601148_fix'
 tag 'documentable'
 tag cci: ['CCI-002476']
 tag nist: ['SC-28 (1)']
 tag ksi:  ['KSI-SVC-SIN']
 tag nist_r4: ['SC-28 (1)']
 tag implementation_status: 'implemented'

 # Encryption at rest: ECR repos encrypted with a KMS CMK (FIPS-validated, HSM-backed
 # key store). require_kms_cmk_encryption=false accepts AWS-managed AES256.
 require_cmk = input('require_kms_cmk_encryption', value: true)
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe aws_ecr_repository(repository_name: name, regions: scan_regions) do
 if require_cmk
 it { should be_kms_encrypted }
 else
 its('encryption_type') { should_not cmp nil }
 end
 end
 end
end
