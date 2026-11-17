control 'SV-233234' do
 title 'The container platform runtime must have security-relevant software updates
 installed within 30 days unless the time period is directed by an authoritative source.'
 desc 'The container platform runtime must be carefully
 monitored for vulnerabilities, and when problems are detected, they must be
 remediated quickly. A vulnerable runtime exposes all containers it supports, as well
 as the host itself, to potentially significant risk. Organizations should use tools
 to look for Common Vulnerabilities and Exposures (CVEs) vulnerabilities in the
 runtimes deployed, to upgrade any instances at risk, and to ensure that
 orchestrators only allow deployments to properly maintained
 runtimes.'
 desc 'check', 'Review documentation and configuration to determine if the container
 platform registry inspects and contains the latest approved vendor repository
 images containing security-relevant updates within 30 days unless the time
 period is directed by an authoritative source. If the container platform registry does not contain the latest image
 with security-relevant updates within 30 days unless the time period is directed
 by an authoritative source, this is a
 finding. The container platform registry should help the user understand from
 where the code in the environment was deployed and must provide controls that
 prevent deployment from untrusted sources or registries.'
 desc 'fix', 'Configure the container platform registry to use
 an approved vendor repository to ensure the latest images containing
 security-relevant updates are installed within 30 days unless the time period is
 directed by an authoritative source.'
 impact 0.5
 tag check_id: 'C-36170r1137635_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233234'
 tag rid: 'SV-233234r1137650_rule'
 tag stig_id: 'SRG-APP-000456-CTR-001130'
 tag gtitle: 'SRG-APP-000456'
 tag fix_id: 'F-36138r1137636_fix'
 tag 'documentable'
 tag cci: ['CCI-002605']
 tag nist: ['SI-2 c']
 tag ksi:  ['KSI-CMT-VTD']
 tag nist_r4: ['SI-2 c']
 tag implementation_status: 'implemented'

 # Security updates installed within window => no unscanned/over-severity images (finding gate).
 ceiling = input('max_image_finding_severity', value: 'HIGH')
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image currency (no unscanned or >#{ceiling}-severity) for #{name}" do
 subject { aws_ecr_repository(repository_name: name, regions: scan_regions).scan_gate_violations(ceiling) }
 it { should be_empty }
 end
 end
end
