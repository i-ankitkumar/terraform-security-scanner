# tfscan

[![CI](https://github.com/i-ankitkumar/terraform-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/i-ankitkumar/terraform-security-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/i-ankitkumar/terraform-security-scanner/blob/main/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

Static security scanner for Terraform, with optional AI-generated remediation guidance.

`tfscan` parses your `.tf` files, runs them through a set of deterministic security and
compliance rules (open security groups, public S3/storage buckets, unencrypted volumes,
overly-permissive IAM, hardcoded secrets, missing tags, unpinned providers), and prints a
severity-ranked report. Pass `--explain` and it will ask Claude to turn each finding into a
short, resource-specific explanation of the risk and the fix — the scanner decides *what* is
wrong (fast, free, reproducible), the model explains *why it matters and how to fix it well*.

## Why

Static analyzers like tfsec/Checkov are great at telling you a rule ID fired. They're less
good at explaining *why* a specific finding matters for *your* specific resource in language
someone can paste into a PR comment or a ticket. `tfscan` keeps the deterministic scanning
(so results are reproducible and don't depend on an API being up) and adds an LLM as an
optional second pass purely for the explanation layer.

## Install

```bash
git clone https://github.com/i-ankitkumar/terraform-security-scanner.git
cd terraform-security-scanner
pip install -e .
```

Requires Python 3.9+.

## Usage

```bash
tfscan ./infra
```

```
Scanned 2 file(s), 10 resource(s).

┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule  ┃ Resource                       ┃ Issue                          ┃ Remediation                     ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ TF001 │ aws_security_group.web         │ Security group open to the     │ Restrict cidr_blocks to known   │
│          │       │ infra/main.tf                  │ internet                       │ IP ranges (office/VPN CIDR) or  │
│          │       │                                │ Ingress rule allows 0.0.0.0/0  │ front the service with a        │
│          │       │                                │ on SSH.                        │ bastion/VPN/load balancer.      │
├──────────┼───────┼────────────────────────────────┼────────────────────────────────┼─────────────────────────────────┤
│ CRITICAL │ TF002 │ aws_s3_bucket.data             │ S3 bucket has a public ACL     │ Set acl to "private" and, if    │
│          │       │ infra/main.tf                  │ acl = "public-read" grants     │ public content is genuinely     │
│          │       │                                │ anonymous internet access to   │ required, serve it through      │
│          │       │                                │ bucket contents.               │ CloudFront with an origin       │
│          │       │                                │                                │ access control instead.         │
└──────────┴───────┴────────────────────────────────┴────────────────────────────────┴─────────────────────────────────┘

critical: 5  high: 2  medium: 1  low: 4
```

Turn on AI-generated, resource-specific remediation text:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
tfscan ./infra --explain
```

Use it as a CI gate — exits non-zero when a finding at or above `--fail-on` is present
(default: `high`):

```bash
tfscan ./infra --fail-on critical
```

## Rules

| ID | Check | Default severity |
|----|-------|-------------------|
| TF001 | Security group / rule open to `0.0.0.0/0` | critical (sensitive ports), high (others) |
| TF002 | S3 bucket ACL set to public | critical |
| TF003 | S3 bucket without server-side encryption | medium |
| TF004 | EBS volume / instance root volume not encrypted | high |
| TF005 | IAM policy with wildcard `Action` | critical |
| TF006 | IAM policy with wildcard `Resource` | high |
| TF007 | Azure storage account allows public blob access | critical |
| TF008 | Azure storage account allows outdated TLS | medium |
| TF009 | Azure storage account allows plain HTTP | high |
| TF010 | Azure NSG rule allows any inbound from the internet | critical |
| TF011 | Hardcoded secret / access key pattern in source | critical |
| TF012 | Taggable resource missing tags (cost/ownership tracking) | low |
| TF013 | Provider version constraint unpinned | low |

Adding a rule is one function in `tfscan/rules.py` and one line in the `RULES` registry —
see the existing rules for the shape.

## How it works

```
.tf files ──▶ parser.py (python-hcl2) ──▶ list[Resource]
                                              │
                                              ▼
                                     rules.py (10 checks)
                                              │
                                              ▼
                                        list[Finding]
                                          │        │
                                (default) │        │ --explain
                                          ▼        ▼
                                  static text   explain.py → Claude
                                          │        │
                                          └───┬────┘
                                              ▼
                                     core.py renders the report
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

`tests/fixtures/insecure.tf` and `tests/fixtures/secure.tf` are the regression fixtures —
the insecure one is expected to trip most rules, the secure one should stay clean.

## Roadmap

- [ ] GitHub Action so this runs automatically on Terraform PRs
- [ ] GCP rules (currently AWS + Azure only)
- [ ] JSON output for piping into other tooling
- [ ] `terraform plan` JSON support, not just static `.tf` source

## About

Built by [Ankit Kumar](https://iankitkumar.in) — DevOps/Cloud engineer working with
Terraform, Azure, and AWS day to day. Part of a series of small, real infra tools;
see [pinned repos](https://github.com/i-ankitkumar) for the others.

## License

MIT
