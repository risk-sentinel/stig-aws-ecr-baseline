control 'SV-233065' do
 title 'The container platform must verify container images.'
 desc 'The container platform must be capable of validating
 container images are signed and that the digital signature is from a recognized and
 approved source approved by the organization. Allowing any container image to be
 introduced into the registry and instantiated into a container can allow for
 services to be introduced that are not trusted and may contain malicious code, which
 introduces unwanted services. These unwanted services can cause harm and security
 risks to the hosting server, the container platform, other services running within
 the container platform, and the overall
 organization.'
 desc 'check', 'Review the container platform configuration to determine if container
 images are verified by enforcing image signing and that the image is signed
 recognized by an approved source. If container images are not verified or the
 signature is not verified as a recognized and approved source, this is a
 finding.'
 desc 'fix', 'Configure the container platform to verify
 container images are digitally signed and the signature is from a recognized and
 approved source.'
 impact 0.5
 tag check_id: 'C-36001r601696_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233065'
 tag rid: 'SV-233065r981844_rule'
 tag stig_id: 'SRG-APP-000131-CTR-000285'
 tag gtitle: 'SRG-APP-000131'
 tag fix_id: 'F-35969r600683_fix'
 tag 'documentable'
 tag cci: ['CCI-003992']
 tag nist: ['CM-14']
 tag nist_r4: ['CM-5 (3)']
 tag implementation_status: 'implemented'

 # Verify images: every in-scope image signed + SBOM-attached (fail-closed).
 repos = ecr_repos_in_scope
 impact 0.0 if repos.empty?
 only_if('No ECR repositories in scope') { !repos.empty? }

 repos.each do |name|
 describe "Image supply-chain (signed + SBOM) for #{name}" do
 subject { aws_ecr_repository(repository_name: name).supply_chain_gaps }
 it { should be_empty }
 end

 # Surfaced separately on purpose. An API error — a denied
 # ecr:ListImageReferrers, a throttle — must never present as "unsigned".
 # Without this the two are indistinguishable, and the check above cannot be
 # believed in either direction: not when it fails, and not when it passes.
 describe "Image supply-chain determinable for #{name} (no API errors)" do
 subject { aws_ecr_repository(repository_name: name).supply_chain_undetermined }
 it { should be_empty }
 end
 end
end
