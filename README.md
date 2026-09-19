# stig-aws-ecr-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_stig-aws-ecr-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_stig-aws-ecr-baseline)

InSpec / CINC Auditor profile validating **Amazon ECR** against the DISA
**Container Platform SRG**, adapted to ECR as the platform — 189 controls across
image scanning, encryption, registry policy, immutability, provenance and the
platform-hardening requirements the SRG carries.

This is the estate's only **DISA-basis** profile. The controls are SRG
requirements mapped onto ECR's actual API surface, with CCI anchors preserved so
a finding traces back to the requirement it came from. Where the SRG asks for
something ECR cannot express, the control says so rather than inventing a proxy.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/stig-aws-ecr-baseline
cd stig-aws-ecr-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**, and for this profile the scoping inputs
change how long the run takes as well as what it covers.

### Credentials

Standard AWS credential resolution. Read-only across the registry surface:

```
ecr:DescribeRepositories       ecr:DescribeImages
ecr:DescribeImageScanFindings  ecr:GetRepositoryPolicy
ecr:GetRegistryScanningConfiguration
ecr:DescribeRegistry           ecr:ListImages
kms:DescribeKey                inspector2:BatchGetAccountStatus
```

### What a first run looks like

Against a real account with several repositories:

**189 controls, 304 results — roughly 148 passed / 47 failed / 109 skipped.**

The skips are largely SRG requirements that ECR cannot express and the
inherited-evidence controls with no manifest configured. If you see far fewer
than 304 results, that is the signal to investigate — a run that assessed
nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Scoping** | `assessed_repositories`, `excluded_repositories` |
| **Policy** | `max_image_finding_severity`, `require_enhanced_scanning`, `require_kms_cmk_encryption`, `pw_min_length` |
| **Allow-list** | `trusted_registry_account_ids` |
| **Attestation** | `leveraged_evidence_base`, `inherited_evidence_uri`, `leveraged_evidence_max_age_days` |

**`assessed_repositories` empty means every repository in the account.** That is
the intended default, and it is not a no-op — with 189 controls, the size of that
list is the difference between a fast scan and a very long one.

**The scanning control is fail-closed.** An image that has never been scanned
fails, the same as one with findings above the threshold. "We do not know" is not
treated as "clean", which is deliberate and occasionally surprising.

---

## Controls

189 controls. The families that carry the most weight:

| Family | Assesses |
|---|---|
| Image scanning | scan-on-push, ENHANCED vs BASIC, finding severity, scan freshness, fail-closed on unscanned |
| Encryption | KMS CMK vs AWS-managed, key policy reachability |
| Registry policy | repository policies, cross-account access, trusted source accounts |
| Immutability | tag mutability, digest-addressable references |
| Platform | the SRG platform-hardening requirements ECR inherits from AWS, evidenced rather than asserted |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/stig-aws-ecr-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-registry-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: stig-aws-ecr-v2r4
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/stig-aws-ecr-baseline
    ref: v0.1.7
    file: /ci/jobs/exec-evidence.yml
    inputs:
      target: my-registry-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: stig-aws-ecr-v2r4
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: the shared evidence-store schema.

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: stig-aws-ecr-v2r4
    git: https://github.com/risk-sentinel/stig-aws-ecr-baseline.git
    tag: v0.1.4
```

Then `include_controls 'stig-aws-ecr-v2r4'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
