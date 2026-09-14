# encoding: UTF-8
#
# aws_ecr_repositories — account-wide ECR repository inventory (ecr:DescribeRepositories,
# paginated). The scope source for the registry-layer controls.
#
#   describe aws_ecr_repositories do
#     its('repository_names') { should_not be_empty }
#   end

class AwsEcrRepositories < AwsResourceBase
  include RegionScope
  name "aws_ecr_repositories"
  desc "All ECR repositories in the account/region."
  example "
    describe aws_ecr_repositories do
      its('repository_names') { should include 'my-app' }
    end
  "

  attr_reader :repositories, :repository_names

  def initialize(opts = {})
    opts = opts.dup
    # Removed BEFORE super: AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    @repositories = []
    @repository_names = []
    # ECR is regional and each region has its OWN registry. A single-region
    # client therefore does not under-report slightly -- it reports confidently
    # on one registry while repositories elsewhere are never seen, and the
    # control passes having found nothing.
    @all_regions = region_scope_or_fail!(@aws, region_override)
    each_region_client(::Aws::ECR::Client) do |client, region|
      next_token = nil
      loop do
        resp = client.describe_repositories(next_token: next_token, max_results: 100)
        Array(resp.repositories).each do |r|
          @repositories << r
          # Region-qualified, so two regions holding a repository of the same
          # name stay distinguishable in the evidence.
          @repository_names << r.repository_name
          @repository_regions ||= {}
          (@repository_regions[r.repository_name] ||= []) << region
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
  end

  # Which region(s) each repository was found in.
  def repository_regions
    @repository_regions ||= {}
  end

  def exists?
    !@repository_names.empty?
  end

  def to_s
    "ECR Repositories"
  end
end
