control 'SV-233061' do
 title 'The container platform must protect audit tools from unauthorized deletion.'
 desc 'Protecting audit data also includes identifying and
 protecting the tools used to view and manipulate log data. Therefore, protecting
 audit tools is necessary to prevent unauthorized operation on audit data.
 Applications providing tools to interface with audit data will leverage user
 permissions and roles identifying the user accessing the tools and the corresponding
 rights the user enjoys in order make access decisions regarding the deletion of
 audit tools. Audit tools include, but are not limited to, vendor-provided and open
 source audit tools needed to successfully view and manipulate audit information
 system activity and records. Audit tools include custom queries and report
 generators.'
 desc 'check', 'Review the container platform to validate container platform audit
 tools are protected from unauthorized deletion. If the audit tools are not
 protected from unauthorized deletion, this is a finding.'
 desc 'fix', 'Configure the container platform to protect audit
 tools from unauthorized deletion.'
 impact 0.5
 tag check_id: 'C-35997r600670_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233061'
 tag rid: 'SV-233061r960945_rule'
 tag stig_id: 'SRG-APP-000123-CTR-000265'
 tag gtitle: 'SRG-APP-000123'
 tag fix_id: 'F-35965r600671_fix'
 tag 'documentable'
 tag cci: ['CCI-001495']
 tag nist: ['AU-9 a']
 tag ksi:  ['KSI-MLA-OSM']
 tag nist_r4: ['AU-9']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
 # infra). Evidence = the leveraged the cloud-provider authorization manifest; Skip (not a
 # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
