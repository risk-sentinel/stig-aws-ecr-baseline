control 'SV-233289' do
 title 'The container platform must use a FIPS-validated cryptographic module to
 implement encryption services for information requiring
 confidentiality.'
 desc 'Unvalidated cryptography is viewed by NIST as
 providing no protection to the information or data. In effect, the data would be
 considered unprotected plaintext. If the agency specifies that the information or
 data be cryptographically protected, then FIPS 140-2/140-3 is applicable. In
 essence, if cryptography is required, it must be validated. Cryptographic modules
 that have been approved for sensitive use may be used in lieu of modules that have
 been validated against the FIPS 140-2/140-3 standard. The cryptographic module used
 must have one FIPS-validated encryption algorithm (i.e., validated Advanced
 Encryption Standard [AES]). This validated algorithm must be used for encryption for
 cryptographic security function within the container platform component and
 information residing in the container platform registry and keystore. This
 requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review the container platform configuration to ensure FIPS-validated
 cryptographic modules are implemented to encrypt information
 requiring confidentiality. If FIPS-validated cryptographic modules are not being
 used, this is a finding.'
 desc 'fix', 'Configure the container platform to use
 FIPS-validated cryptographic modules to encrypt information requiring
 confidentiality.'
 impact 0.7
 tag check_id: 'C-36225r601354_chk'
 tag severity: 'high'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233289'
 tag rid: 'SV-233289r1137648_rule'
 tag stig_id: 'SRG-APP-000635-CTR-001405'
 tag gtitle: 'SRG-APP-000635'
 tag fix_id: 'F-36193r601355_fix'
 tag 'documentable'
 tag cci: ['CCI-002450']
 tag nist: ['SC-13 b']
 tag ksi:  ['KSI-SVC-SIN', 'KSI-SVC-VRI']
 tag nist_r4: ['SC-13']
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
