# frozen_string_literal: true
#
# SDK gems for every service this repository's region_coverage_manifest.yml
# watches. Listed literally, at the top of a file of their own, because
# `Aws.config[:<service>]` raises "invalid configuration option" until the gem
# that registers that config key is loaded.
#
# Why a separate file: the service set differs per repository, but
# region_coverage_test.rb is shared and must stay byte-identical across the
# fleet. Isolating the variance here keeps that true, and keeps every `require`
# a plain top-of-file statement rather than a dynamic one inside a loop.
#
# Adding a manifest entry for a NEW service? Add its require below. You do not
# have to remember: region_coverage_test.rb reconciles this list against the
# manifest and fails with the exact line to add.

require "aws-sdk-ecr"
