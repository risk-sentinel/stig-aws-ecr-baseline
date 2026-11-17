control 'SV-233233' do
 title 'The container platform registry must contain the latest images with most recent
 security-relevant software updates within 30 days unless the time period is directed
 by an authoritative source.'
 desc 'Software supporting the container platform, images in
 the registry must stay up to date with the latest patches, service packs, and hot
 fixes. Not updating the container platform and container images will expose the
 organization to vulnerabilities. Flaws discovered during security assessments,
 continuous monitoring, incident response activities, or information system error
 handling must also be addressed expeditiously. Organization-defined time periods for
 updating security-relevant container platform components may vary based on a variety
 of factors including, for example, the security category of the information system
 or the criticality of the update (i.e., severity of the vulnerability related to the
 discovered flaw). This requirement will apply to software patch management solutions
 that are used to install patches across the enclave and to applications themselves
 that are not part of that patch management solution. For example, many browsers
 today provide the capability to install their own patch software. Patch criticality,
 as well as system criticality will vary. Therefore, the tactical situations
 regarding the patch management process will also vary. This means that the time
 period utilized must be a configurable parameter. Time frames for application of
 security-relevant software updates may be dependent upon the Information Assurance
 Vulnerability Management (the vulnerability-management program) process. The container platform components will be
 configured to check for and install security-relevant software updates within an
 identified time period from the availability of the update. The container platform
 registry will ensure the images are current. The specific time period will be
 defined by an authoritative source.'
 desc 'check', 'Review documentation and configuration to determine if the container
 platform registry inspects and contains the latest approved vendor repository
 images containing security-relevant updates within 30 days unless the time
 period is directed by an authoritative source (an authoritative source, etc.).
 If the container platform registry does not contain the latest image with
 security-relevant updates within 30 days unless a time period directed by the
 authoritative source, this is a finding. The container platform registry should
 help the user understand where the code in the environment was deployed from,
 and must provide controls that prevent deployment from untrusted sources or
 registries.'
 desc 'fix', 'Configure the container platform registry to use
 an approved vendor repository to ensure the latest images containing
 security-relevant updates are installed within 30 days unless a time period is
 directed by an authoritative source (an authoritative source, etc.).'
 impact 0.5
 tag check_id: 'C-36169r1137632_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233233'
 tag rid: 'SV-233233r1137649_rule'
 tag stig_id: 'SRG-APP-000456-CTR-001125'
 tag gtitle: 'SRG-APP-000456'
 tag fix_id: 'F-36137r1137633_fix'
 tag 'documentable'
 tag cci: ['CCI-002605']
 tag nist: ['SI-2 c']
 tag ksi:  ['KSI-CMT-VTD']
 tag nist_r4: ['SI-2 c']
 tag implementation_status: 'implemented'

 # Registry-layer: "latest images with security updates" => no in-scope image is
 # unscanned or carrying findings above max_image_finding_severity (fail-closed:
 # unscanned == unproven == violation). scan-on-push itself is CTR-001335.
 ceiling = input('max_image_finding_severity', value: 'HIGH')
 repos = ecr_repos_in_scope
 scan_regions = ecr_scan_regions
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image scan gate for #{name} (no unscanned or >#{ceiling}-severity images)" do
 subject { aws_ecr_repository(repository_name: name, regions: scan_regions).scan_gate_violations(ceiling) }
 it { should be_empty }
 end
 end
end
