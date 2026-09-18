# Keep a failing collection assertion's evidence intact.
#
# RSpec's object formatter truncates the value it inspects at 200 characters and
# splices an ellipsis into the middle. For a scalar that is a kindness. For the
# assertion this profile family leans on most —
#
#     its('violations') { should be_empty }
#
# — it is evidence loss. The rendered message keeps the FIRST violation and the
# LAST one and drops everything between, so a control reporting forty findings
# ships two of them. The middle is not shortened in a viewer; it never reaches
# the HDF document, and nothing downstream can recover it.
#
# Measured on the pinned auditor image against a forty-element collection: the
# message is 246 characters with a mid-string ellipsis, carrying 2 of 40
# violations. With the cap raised it is 2402 characters and carries all 40.
#
# This file is loaded before any control is evaluated, which is what makes it
# the cheap fix: it needs no control edits, changes no result counts, and
# changes no `code_desc` — every resource here defines `to_s`, so the described
# object still renders as its short form.
#
# The cap is raised, not removed. `nil` disables truncation entirely, and a
# control that somehow enumerated a pathological collection could then write an
# unbounded string into the evidence document. Ten thousand characters is far
# past any real finding list and still bounded.
#
# Rescued rather than assumed: this reaches into RSpec's internals, and a
# profile that fails to LOAD is worse than one whose failure messages are
# clipped. If the constant or the setter ever moves, the profile still runs and
# says why it did not take effect.
begin
  require 'rspec/support/object_formatter'

  formatter = RSpec::Support::ObjectFormatter.default_instance
  current   = formatter.max_formatted_output_length

  # Never lower a cap somebody else raised on purpose. `nil` already means "do
  # not truncate", which is strictly more evidence than this asks for.
  formatter.max_formatted_output_length = 10_000 if current && current < 10_000
rescue LoadError, NameError, NoMethodError => e
  warn "evidence fidelity: failing collection assertions will be truncated by " \
       "RSpec (#{e.class}: #{e.message})"
end
