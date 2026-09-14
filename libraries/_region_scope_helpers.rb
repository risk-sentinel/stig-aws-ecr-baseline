# encoding: UTF-8
#
# _region_scope_helpers — one region walk, shared by every regional resource.
#
# BUG THIS FIXES: resources bound to a single `@aws.<service>_client` only ever
# see the region named by `aws_region`. A workload in any other region is not
# assessed, and the control does not fail -- it finds nothing and passes. Users
# running outside the region we scan reported whole services reading as clean or
# Not Applicable while their estate went unexamined.
#
# The second half of the bug is subtler and was present even in the resources
# that already walked regions: a region that denied the call logged a warning and
# contributed zero rows, so an inaccessible region was indistinguishable from an
# empty one. `Inspec::Log.warn` is not evidence -- nothing reads it, and the HDF
# says PASS. Region failures are therefore collected and surfaced through the
# `connection_error` convention this profile already uses, which renders as a
# skip with rationale rather than a pass.
#
# The leading underscore sorts this ahead of the resources that include it, in
# InSpec's alphabetical library-load order.
#
# Resource scope cannot call `input()` -- it raises there -- so the region
# override is always passed in by the caller rather than read here.

module RegionScope
  # Sweep every enabled region in the partition. Must be asked for explicitly.
  ALL_REGIONS = "*".freeze

  # Resolve which regions to walk.
  #
  # The consumer's `scan_regions` decides, and it must SAY something:
  #
  #   ["us-east-1", "us-west-2"]  -> exactly those
  #   ["*"]                       -> every enabled region in the partition
  #   []                          -> ERROR. We refuse to guess.
  #
  # Empty used to mean "discover everything". That was safe but silent: nothing
  # in the evidence recorded whether a narrow scan was intended or accidental,
  # and the same empty input meant "current region only" in another profile --
  # the same knob with two opposite meanings across the fleet. An assessor
  # reading the HDF could not tell which had happened.
  #
  # So empty is now an error the caller must surface. A full sweep is still
  # available, but only by asking for it, which puts the intent in the inputs
  # where an assessor can see it.
  #
  # Returns [regions, error]. A nil error means the list is trustworthy; a
  # non-nil error means we could not establish scope, which callers must surface
  # rather than treat as "no regions, nothing to check".
  def resolve_region_scope(aws, override = [])
    wanted = Array(override).map(&:to_s).map(&:strip).reject(&:empty?)

    if wanted.empty?
      return [[], "no scan_regions supplied -- refusing to assess a single region " \
                  "silently. Set scan_regions to the regions in scope, or to " \
                  "[\"#{ALL_REGIONS}\"] to sweep every enabled region in the partition."]
    end

    return [wanted, nil] unless wanted.include?(ALL_REGIONS)

    begin
      regions = aws.compute_client.describe_regions.regions.map(&:region_name)
      return [[], "describe_regions returned no regions"] if regions.empty?
      [regions, nil]
    rescue ::Aws::Errors::ServiceError, ::Aws::Errors::MissingRegionError => e
      [[], "could not enumerate regions (#{e.class}: #{e.message})"]
    end
  end

  # Establish scope, or fail the resource loudly.
  #
  # Preferred over calling resolve_region_scope directly. On failure it marks the
  # resource failed in InSpec core, so EVERY control using it reports the reason
  # -- without each control having to remember to assert a scope error. There are
  # 83 call sites across this fleet; relying on each one to check would guarantee
  # some of them silently did not, which is the exact failure being designed out.
  #
  # Returns the regions, or [] having already failed the resource.
  def region_scope_or_fail!(aws, override = [])
    regions, error = resolve_region_scope(aws, override)
    return regions if error.nil?

    @failed_resource  = true
    @connection_error = error
    fail_resource(error)
    []
  end

  # Walk regions, collecting rows. The block is called with each region name and
  # should return an array of rows for it.
  #
  # Returns [rows, errors] where errors maps region => message. A region that
  # errors contributes no rows AND an entry in errors, so the caller can tell the
  # two apart. Callers must not treat a non-empty errors hash as a clean result.
  def each_region_collecting(regions)
    rows = []
    errors = {}
    Array(regions).each do |region|
      begin
        rows.concat(Array(yield(region)))
      rescue ::Aws::Errors::ServiceError => e
        errors[region] = "#{e.class}: #{e.message}"
      rescue StandardError => e
        errors[region] = "#{e.class}: #{e.message}"
      end
    end
    [rows, errors]
  end

  # Yield a freshly constructed, region-bound client per region.
  #
  # The sibling of each_region_collecting, for resources that accumulate into
  # their own structures rather than returning rows. Clients are constructed
  # DIRECTLY rather than through @aws.aws_client: that accessor caches by class
  # with no region in the key, so every region would be serialised through one
  # client bound to one region -- the original bug, reintroduced.
  #
  # A region that raises is recorded in region_errors and skipped, so a partial
  # sweep is visible rather than passing as a complete one.
  def each_region_client(klass)
    @region_errors ||= {}
    Array(@all_regions).each do |region|
      begin
        yield(klass.new(region: region), region)
      rescue StandardError => e
        @region_errors[region] = "#{e.class}: #{e.message}"
      end
    end
  end

  def region_errors
    @region_errors ||= {}
  end

  def regions_scanned
    Array(@all_regions) - region_errors.keys
  end

  # Page through a list call until the cursor is exhausted, returning every
  # response so the caller can take whichever member it needs.
  #
  # WHY THIS EXISTS: several resources called describe_* once and used the first
  # page. AWS caps most list calls, so past that cap they silently under-report --
  # the same defect as region blindness, one axis over. A control then passes
  # against a partial set, and nothing in the evidence says the answer was cut off.
  #
  # Covers the cursor styles in use: next_token, marker/next_marker.
  #
  # Refuses to return a partial answer quietly. A cursor that does not advance
  # would otherwise spin forever, and a silent break would hand back a truncated
  # result that looks complete -- so both raise.
  def paginate_all(cursor: :next_token, args: {}, max_pages: 200)
    responses = []
    token = nil
    pages = 0
    loop do
      call_args = args.dup
      call_args[cursor] = token if token
      resp = yield(call_args)
      break if resp.nil?
      responses << resp
      nxt = resp.respond_to?(cursor) ? resp.public_send(cursor) : nil
      nxt = resp.next_marker if nxt.nil? && resp.respond_to?(:next_marker)
      break if nxt.nil? || nxt.to_s.empty?
      raise "paginate_all: cursor #{cursor} did not advance -- refusing to loop" if nxt == token
      pages += 1
      if pages > max_pages
        raise "paginate_all: exceeded #{max_pages} pages -- refusing to return a partial answer silently"
      end
      token = nxt
    end
    responses
  end

  # Route a single-target lookup to the right region.
  #
  # An ARN carries its own region, so an identifier that is one answers the
  # question by itself. Otherwise an explicit `region:` wins, and failing both we
  # fall back to the default client's region -- which is correct when the caller
  # passed a bare name, since a bare name is only meaningful in one region
  # anyway.
  def client_region_for(identifier, explicit = nil)
    return explicit.to_s unless explicit.to_s.empty?
    parts = identifier.to_s.split(':')
    return parts[3] if parts.length > 3 && parts[0] == 'arn' && !parts[3].to_s.empty?
    nil
  end

  # Render region failures as a connection_error string, or nil when every region
  # answered. Kept separate so a resource can decide whether partial data is
  # usable, but the default is that it is not.
  def region_error_summary(errors, scanned)
    return nil if errors.nil? || errors.empty?
    detail = errors.map { |r, m| "#{r}: #{m}" }.join("; ")
    "#{errors.size} of #{scanned} region(s) could not be read -- #{detail}. " \
      "Results are incomplete; treat this as unassessed rather than clean."
  end
end
