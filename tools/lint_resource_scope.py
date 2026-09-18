#!/usr/bin/env python3
"""Fail on InSpec resource calls made in a `describe` BODY.

A describe body is an RSpec example GROUP, not an example. Calling a resource
there raises at exec time:

    RSpec::Core::ExampleGroup::WrongScopeError
    `aws_ecr_repository` is not available on an example group

Neither `cinc-auditor check` nor `json` evaluates control bodies, so both pass
on the broken code. This shipped in v0.1.4 and broke the consumer's exec leg.

LEGAL, and must not be flagged:
    describe aws_ecr_repository(name: n) do   # resource is an ARGUMENT
    subject { aws_ecr_repository(name: n) }   # deferred into an example
    it { ... }  /  before  /  let

ILLEGAL:
    describe 'x' do
      aws_ecr_repository(name: n).something   # bare call in the group body
    end

Implementation note: a naive depth counter is wrong. Decrementing on every
`end` lets the `end` of an inner `it ... do` block close the describe frame,
after which the rest of the body goes unchecked — that mistake made the first
version of this linter pass the very code it was written to catch. A stack is
required so each `end` pops the frame it actually belongs to.

SECOND RULE — a control-scope HELPER called inside a deferred block.

The mirror image of the first, and it caught nothing until it existed:

    describe 'EBS volumes with encryption disabled' do
      subject { aws_ebs_volumes_multi_region(regions: compute_scan_regions)... }

    undefined local variable or method 'compute_scan_regions'
      for #<RSpec::ExampleGroups::EBSVolumesWithEncryptionDisabled>

`subject { }` is deferred into the example, which is exactly why calling a
RESOURCE there is legal. A helper is different: helpers reach controls through
`::Inspec::Rule.include(SomeModule)`, so they exist on the control, and the
example is not the control. Deferring the call moves it out of the scope that
has the method.

The helper names are not hard-coded. They are read from `libraries/`: every
module passed to `::Inspec::Rule.include(...)`, and every public method it
defines above `private`. So a new helper is covered the moment it is included,
and a private one — which controls cannot call anyway — is not.

The same call is LEGAL at control scope, which is where the working call sites
put it:

    describe aws_ecs_task_sets(regions: compute_scan_regions) do   # argument
    inv = aws_lightsail_inventory(regions: compute_scan_regions)   # local

Both defects shipped in a tagged release and were invisible to `check` and
`json`, which load control files without evaluating a single control body.
"""
import re
import sys
from pathlib import Path

RESOURCE = re.compile(r"\baws_[a-z0-9_]+\(")
# A block opener: a trailing `do` (with optional |args|), or a keyword that
# opens a block needing `end`. Anchored at line start so a MODIFIER form
# (`impact 0.0 if repos.empty?`) does not push a frame.
# The optional block-args group absorbs its own leading whitespace, so there
# are never two adjacent variable-length matchers to backtrack between. `[ \t]`
# rather than `\s` because this is matched per-line.
DO_BLOCK = re.compile(r"\bdo\b(?:[ \t]*\|[^|]*\|)?[ \t]*$")
KEYWORD_BLOCK = re.compile(r"^(if|unless|case|begin|def|class|module|while|until)\b")
END = re.compile(r"^end\b")
DESCRIBE = re.compile(r"^(describe|context)\b")
DEFERRED = re.compile(r"^(it|its|subject|before|after|let|let!|specify|example)\b")

DESCRIBE_FRAME = "describe"
DEFERRED_FRAME = "deferred"
OTHER_FRAME = "other"


RULE_INCLUDE = re.compile(r"::?Inspec::Rule\.include\(\s*([A-Z]\w*)")
MODULE_DEF = re.compile(r"^module\s+([A-Z]\w*)\s*$", re.M)
DEF_LINE = re.compile(r"^\s+def\s+([a-z_][a-z0-9_]*[?!]?)", re.M)
PRIVATE_LINE = re.compile(r"^\s+private\s*$", re.M)


def control_scope_helpers(roots):
    """Every method a control can call because a module was included into Rule.

    Only the public ones: a `private` method is unreachable from a control body
    in the first place, so flagging it would be noise. Read from the source
    rather than listed here, so this does not need editing when a helper is
    added.
    """
    names = set()
    for root in roots:
        for lib in sorted(Path(root).rglob("*.rb")):
            text = lib.read_text()
            included = set(RULE_INCLUDE.findall(text))
            if not included:
                continue
            for m in MODULE_DEF.finditer(text):
                if m.group(1) not in included:
                    continue
                body = text[m.end():]
                end = re.search(r"^end\s*$", body, re.M)
                body = body[:end.start()] if end else body
                cut = PRIVATE_LINE.search(body)
                if cut:
                    body = body[:cut.start()]
                names.update(DEF_LINE.findall(body))
    return names


def helper_calls(line, helpers):
    """Helper names invoked on this line, ignoring definitions and receivers."""
    hits = []
    for name in helpers:
        if re.search(rf"(?<![.\w:]){re.escape(name)}\b", line) and not re.match(
            rf"\s*def\s+{re.escape(name)}\b", line
        ):
            hits.append(name)
    return sorted(hits)


def _classify(line: str) -> str:
    """Which kind of frame this line would open, if it opens one."""
    if DESCRIBE.match(line):
        return DESCRIBE_FRAME
    if DEFERRED.match(line):
        return DEFERRED_FRAME
    return OTHER_FRAME


def _opens_block(line: str) -> bool:
    return bool(DO_BLOCK.search(line)) or bool(KEYWORD_BLOCK.match(line))


def _in_describe_body(stack) -> bool:
    """True when the innermost enclosing example group is a describe.

    A deferred frame (it/subject/let) between here and the describe means the
    code runs inside an EXAMPLE, where resources are available.
    """
    for frame in reversed(stack):
        if frame == DEFERRED_FRAME:
            return False
        if frame == DESCRIBE_FRAME:
            return True
    return False


def _in_deferred(stack) -> bool:
    """True when this line runs inside an EXAMPLE rather than on the control.

    Any deferred frame anywhere in the stack is enough: once execution is inside
    an `it`/`subject`/`let`, a nested `if` or `each` is still the example.
    """
    return DEFERRED_FRAME in stack


def _is_violation(line: str, kind: str, stack) -> bool:
    # A resource on the `describe ... do` line is an ARGUMENT — legal.
    # A resource on an it/subject/let line is deferred — legal.
    return kind == OTHER_FRAME and _in_describe_body(stack) and bool(RESOURCE.search(line))


def violations(path: Path, helpers=frozenset()):
    """(lineno, line, kind) for each violation; kind is 'resource' or 'helper'."""
    stack = []
    out = []

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        kind = _classify(line)
        if _is_violation(line, kind, stack):
            out.append((lineno, line, "resource"))

        # A deferred ONE-LINER never opens a frame — `subject { ... }` closes on
        # its own line — so it has to be judged here rather than by the stack.
        deferred_here = kind == DEFERRED_FRAME and "{" in line
        if helpers and (deferred_here or _in_deferred(stack)):
            for name in helper_calls(line, helpers):
                out.append((lineno, f"{line}   [helper: {name}]", "helper"))

        if END.match(line) and stack:
            stack.pop()
        elif _opens_block(line):
            stack.append(kind)

    return out



# --- rule 3: a strictly fail-closed resource must be given its region scope ----
#
# A resource whose library calls `region_scope_or_fail!` refuses to run without a
# region list. Some of them first try `client_region_for`, which resolves a
# region from an ARN or region-qualified identifier — those legitimately need no
# argument, because the caller has already said where to look. The rest MUST be
# handed `regions:` at every call site, or they fail closed at exec with
#
#     no scan_regions supplied -- refusing to assess a single region silently
#
# which reads as a finding and is really a wiring bug. That happened twice:
# C-6.2/C-6.6, then C-6.8 — and C-6.8 hid behind a conditional, so it only
# appeared once a consumer populated the input that reached the branch. Neither
# `check` nor `json` can see it: both only load the control.

EXAMPLE_HEREDOC_RE = re.compile(r"^\s*example\s+<<[-~]?([A-Z]+)\b.*?^\s*\1\s*$",
                                re.M | re.S)
EXAMPLE_QUOTED_RE = re.compile(r"^\s*example\s+([\"']).*?\1\s*$", re.M | re.S)


def _without_examples(body: str) -> str:
    """Drop `example` blocks before looking for call sites.

    A resource's own usage example shows the terse form on purpose — it
    documents the resource, it does not construct one at exec. Counting it as a
    call site flags every well-documented resource in the profile, which is the
    fastest way to get a linter ignored.
    """
    body = EXAMPLE_HEREDOC_RE.sub("", body)
    return EXAMPLE_QUOTED_RE.sub("", body)


STRICT_NAME_RE = re.compile(r'^\s*name\s+"([a-z0-9_]+)"', re.M)


def strict_region_resources(roots):
    """Resource names that fail closed with no identifier-based escape hatch."""
    names = set()
    for root in roots:
        for lib in Path(root).rglob("*.rb"):
            body = lib.read_text(encoding="utf-8", errors="replace")
            if "region_scope_or_fail!" not in body:
                continue
            if "client_region_for" in body:
                continue  # resolves its own region from the identifier
            m = STRICT_NAME_RE.search(body)
            if m:
                names.add(m.group(1))
    return names


# Longest argument list we will scan before giving up on finding the closing
# paren. Generous: the point is to bound a runaway scan on malformed source, not
# to limit real calls.
MAX_ARG_SPAN = 2000


def _argument_text(body: str, open_paren: int) -> str:
    """The text between a call's parentheses, balanced across newlines.

    A call that HAS a region scope is usually the one someone wrapped over
    several lines, so a line-at-a-time read would miss exactly the cases the
    rule exists to pass.
    """
    depth = 0
    for i in range(open_paren, min(len(body), open_paren + MAX_ARG_SPAN)):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return body[open_paren + 1:i]
    # Unbalanced within the span: fall back to a prefix so the call is still
    # reported rather than silently skipped.
    return body[open_paren + 1:open_paren + 200]


def _calls_without_regions(body: str, name: str):
    """(lineno, rendered call) for each construction of `name` lacking regions:."""
    for m in re.finditer(rf"\b{re.escape(name)}\(", body):
        args = _argument_text(body, m.end() - 1)
        if "regions" in args:
            continue
        yield body[:m.start()].count("\n") + 1, f"{name}({args.strip()[:80]})"


def region_argument_violations(path: Path, strict):
    """Calls to a strict resource whose argument list carries no `regions:`."""
    if not strict:
        return []
    body = _without_examples(path.read_text(encoding="utf-8", errors="replace"))
    return [hit for name in strict for hit in _calls_without_regions(body, name)]


# One message per rule. Kept beside each other so the three read as a set: every
# one of them describes an error that only appears on a live exec, which is why
# a linter carries them at all.
RULE_MESSAGES = {
    "resource": (
        "InSpec resource called in a describe body — raises WrongScopeError at "
        "exec. Resolve it at control scope instead."
    ),
    "helper": (
        "control-scope helper called inside a deferred block — raises NameError "
        "at exec, because the example is not the control. Resolve it at control "
        "scope and close over the value."
    ),
    "regions": (
        "a resource that fails closed without a region scope is constructed with "
        "no `regions:` — it will report \"no scan_regions supplied\" at exec, "
        "which reads as a finding and is a wiring bug. "
        "Pass regions: Array(input('scan_regions'))."
    ),
}


def _report(found) -> bool:
    """Print every rule's hits. True when anything was found."""
    any_found = False
    for kind, message in RULE_MESSAGES.items():
        hits = found.get(kind) or []
        if not hits:
            continue
        any_found = True
        print(f"::error::{message}")
        for hit in hits:
            print(f"  {hit}")
    return any_found


def main(argv):
    targets = []
    for root in argv[1:] or ["controls", "libraries"]:
        targets.extend(Path(root).rglob("*.rb"))

    helpers = control_scope_helpers(["libraries"])
    if not helpers:
        # Say it out loud. A profile can legitimately have none — helpers reached
        # through a constant (`SomeHelper.method`) resolve in any scope and carry
        # no hazard — but "found nothing to check" and "checked and found nothing
        # wrong" must not print the same way.
        print("::notice::no modules are included into ::Inspec::Rule under libraries/, "
              "so the deferred-helper rule has nothing to check in this profile.")

    strict = strict_region_resources(["libraries"])
    if not strict:
        # Same discipline as the helper notice: "nothing to check" and "checked,
        # found nothing" must not print identically.
        print("::notice::no library calls region_scope_or_fail! without a "
              "client_region_for fallback, so the region-argument rule has nothing "
              "to check in this profile.")

    found = {"resource": [], "helper": [], "regions": []}
    for f in sorted(targets):
        for lineno, line, kind in violations(f, helpers):
            found[kind].append(f"{f}:{lineno}: {line[:110]}")
        for lineno, call in region_argument_violations(f, strict):
            found["regions"].append(f"{f}:{lineno}: {call}")

    if _report(found):
        return 1

    print(f"OK — no resource calls in describe bodies, no control-scope helpers "
          f"in deferred blocks, and every strictly region-scoped resource is given "
          f"its scope ({len(targets)} file(s), {len(helpers)} helper(s), "
          f"{len(strict)} strict resource(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
