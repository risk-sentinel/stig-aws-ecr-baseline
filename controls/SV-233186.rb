control 'SV-233186' do
 title 'The container platform registry must prohibit installation or modification of
 container images without explicit privileged status.'
 desc 'Controlling access to those users and roles that
 perform container platform registry functions reduces the risk of untested or
 potentially malicious containers from being introduced into the platform. This
 access may be separate from the access required to instantiate container images into
 services and those access requirements required to perform patch management and
 upgrades within the container platform. Explicit privileges (escalated or
 administrative privileges) provide the regular user with explicit capabilities and
 control that exceeds the rights of a regular
 user.'
 desc 'check', "Review container platform registry security settings with respect to
 nonadministrative users' ability to create, alter, or replace container images.
 If any such permissions exist and are not documented and approved, this is a
 finding."
 desc 'fix', 'Document and obtain approval for any
 nonadministrative users who require the ability to create, alter, or replace
 container images within the container platform registry. Implement the approved
 permissions. Revoke any unapproved permissions.'
 impact 0.5
 tag check_id: 'C-36122r981886_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233186'
 tag rid: 'SV-233186r981888_rule'
 tag stig_id: 'SRG-APP-000378-CTR-000890'
 tag gtitle: 'SRG-APP-000378'
 tag fix_id: 'F-36090r981887_fix'
 tag 'documentable'
 tag cci: ['CCI-003980']
 tag nist: ['CM-11 (2)']
 tag nist_r4: ['CM-11 (2)']
 tag implementation_status: 'implemented'
 tag fsbp: 'ECR.2'

 # Registry-layer ECR assertion (tag immutability); account-wide, scoped via excluded_repositories.
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe aws_ecr_repository(repository_name: name, regions: scan_regions) do
 it { should be_immutable }
 end
 end
end
