# encoding: UTF-8

control 'ecr-registry-inventory' do
 impact 0.0
 title 'ECR registry inventory (informational)'
 desc "
 Enumerates every ECR repository in the account/region so the HDF records the full
 assessed registry surface, and flags which repositories are excluded from scoring
 via excluded_repositories input. Most organizations run more than one registry;
 the per-repository registry controls iterate this in-scope set and score each repo
 independently (pass/fail per repo).

 Informational only: impact 0.0 renders this Not Applicable in the HDF rollup — it is
 scope/provenance metadata, never a pass or fail.
 "
 tag scan_target: true
 tag implementation_status: 'inherited'

 scan_regions = ecr_scan_regions
 all_repos = aws_ecr_repositories(regions: scan_regions).repository_names
 excluded = excluded_repositories_list
 in_scope = ecr_repos_in_scope

 # Resolved HERE, at control-body scope. An InSpec resource cannot be called
 # from inside a `describe` block — RSpec raises WrongScopeError, because a
 # describe body is an example GROUP, not an example. Resources are only
 # available at control scope (as above) or inside an `it`/`before`/`let`.
 # `check` and `json` do not evaluate control bodies, so this only surfaces on
 # a real exec.
 orphans_by_repo = in_scope.sort.each_with_object({}) do |name, acc|
 found = aws_ecr_repository(repository_name: name, regions: scan_regions).orphan_supply_chain_artifacts
 acc[name] = found unless found.empty?
 end

 describe 'ECR registry inventory' do
 if all_repos.empty?
 it('no ECR repositories found in this account/region') { expect(true).to eq true }
 else
 it("repositories found = #{all_repos.length}; in scope = #{in_scope.length}; excluded = #{excluded.length}") do
 expect(true).to eq true
 end
 all_repos.sort.each do |name|
 flag = excluded.include?(name) ? ' [EXCLUDED]' : ''
 it("repository: #{name}#{flag}") { expect(true).to eq true }
 end

 # Reverse resolution: supply-chain artifacts whose subject digest is
 # not a current image here. Either the image was replaced and its signature
 # left behind, or the subject is a child manifest of a multi-arch Image
 # Index. Informational like the rest of this control — an orphan is
 # provenance metadata, not a compliance failure — but it must be VISIBLE,
 # because from the forward direction alone it is indistinguishable from
 # there being no signature at all.
 orphans_by_repo.each do |name, found|
 found.each do |o|
 it("#{name} — orphaned supply-chain artifact #{o}") { expect(true).to eq true }
 end
 end
 end
 end
end
