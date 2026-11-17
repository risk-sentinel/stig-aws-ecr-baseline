control 'SV-233072' do
 title 'The container platform registry must contain only container images for those
 capabilities being offered by the container platform.'
 desc 'Allowing container images to reside within the
 container platform registry that are not essential to the capabilities being offered
 by the container platform becomes a potential security risk. By allowing these
 non-essential container images to exist, the possibility for accidental
 instantiation exists. The images may be unpatched, not supported, or offer
 non-approved capabilities. Those images for customer services are considered
 essential
 capabilities.'
 desc 'check', 'Review the container platform registry and the container images being
 stored. If container images are stored in the registry and are not being used to
 offer container platform capabilities, this is a finding.'
 desc 'fix', 'Remove all container images from the container
 platform registry that are not being used or contain features and functions not
 supported by the platform.'
 impact 0.5
 tag check_id: 'C-36008r600703_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233072'
 tag rid: 'SV-233072r960963_rule'
 tag stig_id: 'SRG-APP-000141-CTR-000320'
 tag gtitle: 'SRG-APP-000141'
 tag fix_id: 'F-35976r600704_fix'
 tag 'documentable'
 tag cci: ['CCI-000381']
 tag nist: ['CM-7 a']
 tag ksi:  ['KSI-CMT-RMV', 'KSI-IAM-JIT']
 tag nist_r4: ['CM-7 a']
 tag implementation_status: 'implemented'

 # Registry-layer ECR assertion (lifecycle keeps only needed images); account-wide, scoped via excluded_repositories.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe aws_ecr_repository(repository_name: name, regions: scan_regions) do
 it { should have_lifecycle_policy }
 end
 end
end
