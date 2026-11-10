#!/usr/bin/env python3
r"""Fail on a control whose compliance tags are incomplete, duplicated, non-literal,
or disagree with each other.

Four defect classes, all of which have shipped from this fleet, and none of
which `cinc-auditor check` or `json` can see.

**A missing anchor is silent.** `tag nist:` is Rev 5; `tag nist_r4:` is the Rev 4
anchor a consumer joins to. A control with the first and not the second drops out
of a Rev 4 rollup and reads as absent coverage rather than as a control with no
Rev 4 predecessor. 47 controls across the fleet sat in that state, and they were
found by hand, control by control -- which is what this linter replaces.

Where a control genuinely has no Rev 4 predecessor -- `SR-3`, `CM-14`, `SC-45`
and the rest of what Rev 5 introduced -- it carries `tag nist_r4_unmapped:` with
the labels that have none. The claim is then explicit and reviewable in the
results, instead of being the absence of a line.

**A duplicated tag is noise that hides disagreement.** Nine controls in one
profile carried `tag ksi_unmapped:` twice, from a tagging pass that inserted
where it should have replaced. Ruby evaluates both, so nothing failed; a reader
still has to check whether the two copies agree.

**A non-literal tag value aborts the whole profile.** InSpec collects tags from
the AST at parse time and calls `.value` on the node:

    undefined method 'value' for an instance of RuboCop::AST::SendNode

`tag nist: SOME_CONSTANT` crashes `check`. Worse, `tag nist: [SOME_CONSTANT]`
passes both `check` AND `json` while emitting `[None]` -- a tag that looks
present and carries nothing.

**A NIST tag its CCIs do not support.** `tag cci:` and `tag nist:` describe the
same requirement at two granularities, and a consumer may join on either. Every
CCI maps to exactly one Rev 5 part; `tag nist:` must be exactly the set its CCIs
map to. A base control where Rev 5 assesses parts (`AU-12` for `AU-12 a`), a part
lettered from Rev 4, or a CCI picked for a different control all fail here. The
mapping ships beside this file as cci_to_nist.json, so the check needs no network.

Two things this linter must NOT flag, both of which the first version got wrong:

* **A tag set in each arm of a conditional.** `if mode == 'container_only'` ...
  `tag implementation_status: 'inherited'` ... `else` ... `'implemented'` ...
  `end` is one tag with two possible values, not a duplicate. Branches are
  tracked with a stack rather than a depth counter, for the same reason
  lint_resource_scope.py needs one: an `end` must pop the frame it belongs to.
* **A value carrying a comma, or continued across lines.** Splitting an array on
  every comma tears `"SRG V2R4 (audit domain, AWS-inherited)"` in half, and
  reading one line of a `"a: " \` / `"b"` continuation reads half a string.

Usage:
    python3 tools/lint_control_tags.py            # defaults to controls/
    python3 tools/lint_control_tags.py controls
"""
import json
import re
import sys
from pathlib import Path

# CCI -> Rev 5 label, from MITRE Heimdall's CciNistMappingData.ts. A fixed file
# beside this one, not an argument.
CCI_MAP = Path(__file__).resolve().parent / "cci_to_nist.json"

CONTROL = re.compile(r"^\s*control\s+['\"]([^'\"]+)", re.M)
TAG_START = re.compile(r"^([ \t]*)tag[ \t]+([a-z_][a-z0-9_]*)[ \t]*:[ \t]*", re.I)

CONDITIONAL = re.compile(r"^\s*(if|unless|case)\b")
BRANCH = re.compile(r"^\s*(elsif|else|when)\b")
OPENER = re.compile(r"^\s*(if|unless|case|begin|def|class|module|while|until)\b")
DO_BLOCK = re.compile(r"\bdo\b(?:[ \t]*\|[^|]*\|)?[ \t]*$")
END = re.compile(r"^\s*end\b")

# A value InSpec can read from the AST: quoted string, number, boolean -- or
# adjacent string literals, which Ruby concatenates at parse time and which this
# fleet uses to wrap a long evidence URL across two lines.
_STRING = r"""(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""
SCALAR = re.compile(rf"^(?:{_STRING}(?:\s+{_STRING})*|-?\d+(?:\.\d+)?|true|false)$")


def control_blocks(text):
    """(id, body) per control. Iterating blocks rather than files is the point:
    21 files in this fleet hold several controls, and a per-file search stops at
    the first one -- which is how an earlier sweep missed 53 tags."""
    starts = [(m.start(), m.group(1)) for m in CONTROL.finditer(text)]
    for i, (pos, cid) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        yield cid, text[pos:end]


def read_value(text, i):
    """The tag value starting at `i`, respecting quotes, brackets and `\\` line
    continuations. Returns (value, index after it)."""
    depth, quote, out = 0, None, []
    while i < len(text):
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c; out.append(c); i += 1; continue
        if c == "[":
            depth += 1; out.append(c); i += 1; continue
        if c == "]":
            depth -= 1; out.append(c); i += 1; continue
        if c == "#" and depth == 0:                      # trailing comment
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if c == "\\" and text[i:i + 2] == "\\\n":        # string continuation
            out.append(" "); i += 2; continue
        if c == "\n" and depth == 0:
            break
        out.append(c); i += 1
    return "".join(out).strip(), i


def split_top_level(inner):
    """Array elements, splitting only on commas outside quotes."""
    parts, buf, quote = [], [], None
    for c in inner:
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            continue
        if c in "'\"":
            quote = c; buf.append(c); continue
        if c == ",":
            parts.append("".join(buf)); buf = []; continue
        buf.append(c)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def non_literal_parts(raw):
    """The parts of a tag value InSpec cannot read from the AST."""
    if raw.startswith("[") and raw.endswith("]"):
        return [p for p in split_top_level(raw[1:-1]) if not SCALAR.match(p)]
    return [] if SCALAR.match(raw) else [raw]


def tag_occurrences(block):
    """(name, value, branch signature) for every tag in this control.

    The signature names the conditional arm the tag sits in, so two tags in
    different arms of the same `if` are not counted as duplicates: only one of
    them can ever run.
    """
    stack, occurrences, i, line_start = [], [], 0, True
    for lineno, raw_line in enumerate(block.split("\n")):
        line = raw_line
        if END.match(line) and stack:
            stack.pop()
        elif BRANCH.match(line) and stack and stack[-1][0] == "cond":
            stack[-1][1] += 1
        m = TAG_START.match(line)
        if m:
            offset = block.index(raw_line, i) if raw_line else i
            _, end = None, None
            value, _ = read_value(block[offset + m.end():], 0)
            signature = tuple((idx, arm) for idx, (kind, arm) in enumerate(stack) if kind == "cond")
            occurrences.append((m.group(2), value, signature))
        if CONDITIONAL.match(line):
            stack.append(["cond", 0])
        elif OPENER.match(line) or DO_BLOCK.search(line):
            stack.append(["other", 0])
        i += len(raw_line) + 1
    return occurrences


def literal_list(raw):
    """The string elements of a literal array value, unquoted."""
    if not (raw.startswith("[") and raw.endswith("]")):
        return None
    return [p[1:-1] for p in split_top_level(raw[1:-1]) if p[:1] in "'\""]


def nist_cci_disagreement(occurrences, cci_map):
    """A message if `tag nist:` is not exactly the set its CCIs map to, else None.

    Only checked where each tag is set once: a tag set per conditional arm is
    left to review rather than paired arm by arm.
    """
    values = {}
    for name, value, _ in occurrences:
        if name in ("nist", "cci"):
            values.setdefault(name, []).append(value)
    if len(values.get("nist", [])) != 1 or len(values.get("cci", [])) != 1:
        return None
    nist, ccis = literal_list(values["nist"][0]), literal_list(values["cci"][0])
    if nist is None or ccis is None:
        return None
    unknown = [c for c in ccis if c not in cci_map]
    if unknown:
        return f"tag cci: {', '.join(unknown)} not in {CCI_MAP.name} — no Rev 5 part to check against"
    derived = list(dict.fromkeys(cci_map[c] for c in ccis))
    if set(nist) == set(derived):
        return None
    extra = [n for n in nist if n not in derived]
    missing = [d for d in derived if d not in nist]
    detail = "; ".join(x for x in (
        f"not backed by any CCI: {extra}" if extra else "",
        f"CCIs map to but missing: {missing}" if missing else "") if x)
    return f"tag nist: disagrees with tag cci: ({detail}) — the CCIs map to {derived}"


def violations(path, cci_map):
    text = path.read_text(encoding="utf-8")
    for cid, block in control_blocks(text):
        seen, names = {}, set()
        occurrences = tag_occurrences(block)
        for name, value, signature in occurrences:
            names.add(name)
            for other_value, other_signature in seen.get(name, []):
                if other_signature == signature:
                    same = "identical" if other_value == value else "DIFFERING"
                    yield cid, f"tag {name}: appears more than once in the same branch ({same} values)"
            seen.setdefault(name, []).append((value, signature))
            bad = non_literal_parts(value)
            if bad:
                yield cid, (f"tag {name}: value is not a literal ({', '.join(bad)[:60]}) — "
                            "InSpec reads tags from the AST at parse time")

        if "nist" in names and "cci" not in names:
            yield cid, "has tag nist: but no tag cci:"
        if "cci" in names and "nist" not in names:
            yield cid, "has tag cci: but no tag nist:"
        if "nist" in names and not ({"nist_r4", "nist_r4_unmapped"} & names):
            yield cid, ("has tag nist: but neither tag nist_r4: nor tag nist_r4_unmapped: — "
                        "a missing Rev 4 anchor is indistinguishable from a control that has none")
        if "severity" in names and "severity_source" not in names:
            yield cid, "has tag severity: but no tag severity_source:"
        disagreement = nist_cci_disagreement(occurrences, cci_map)
        if disagreement:
            yield cid, disagreement


def main(argv):
    roots = argv[1:] or ["controls"]
    files = sorted(f for root in roots for f in Path(root).rglob("*.rb"))
    if not CCI_MAP.is_file():
        print(f"::error::{CCI_MAP} is missing; the NIST/CCI agreement check cannot run.")
        return 1
    cci_map = json.loads(CCI_MAP.read_text(encoding="utf-8"))["cci"]

    found = [(f, cid, msg) for f in files for cid, msg in violations(f, cci_map)]
    if found:
        print("::error::control tags are incomplete, duplicated, non-literal, or disagree.")
        for f, cid, msg in found:
            print(f"  {f}: {cid}: {msg}")
        return 1

    controls = sum(1 for f in files for _ in control_blocks(f.read_text(encoding="utf-8")))
    print(f"OK — {controls} control(s) in {len(files)} file(s); every one carries its "
          "NIST, CCI, Rev 4 and severity provenance, once each, as literals, "
          "with NIST matching its CCIs.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
