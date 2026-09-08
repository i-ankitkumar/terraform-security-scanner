"""Turn a static finding into a plain-English, resource-specific remediation.

Works with zero configuration (falls back to the rule's canned remediation
text). Set ANTHROPIC_API_KEY to get a short, tailored explanation per
finding instead — this is the "AI" layer on top of the deterministic
scanner: the scanner decides *what* is wrong (fast, free, reproducible),
the model decides how to *explain and fix it well* (nuanced, costs a
token or two).
"""

from __future__ import annotations

import os

from tfscan.rules import Finding

_PROMPT_TEMPLATE = """You are a senior cloud security engineer reviewing a Terraform \
misconfiguration for a teammate. Be concrete and brief.

Finding: {title}
Resource: {resource_address}
Detail: {detail}
Default guidance: {remediation}

In 2-3 sentences: explain the concrete risk in plain English (who could do what, \
and what could go wrong), then give one specific Terraform-level fix. \
No preamble, no markdown headers."""


def explain_findings(findings: list[Finding]) -> dict[str, str]:
    """Return {"RULE_ID:resource_address": explanation} for findings we could explain.

    Missing entries mean "use the finding's own .remediation text" — callers
    should treat this dict as an overlay, not a full mapping.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key or not findings:
        return {}

    try:
        import anthropic
    except ImportError:
        return {}

    client = anthropic.Anthropic(api_key=api_key)
    explanations: dict[str, str] = {}

    for finding in findings:
        key = f"{finding.rule_id}:{finding.resource_address}"
        try:
            response = client.messages.create(
                model=os.environ.get("TFSCAN_MODEL", "claude-haiku-4-5"),
                max_tokens=200,
                messages=[
                    {
                        "role": "user",
                        "content": _PROMPT_TEMPLATE.format(
                            title=finding.title,
                            resource_address=finding.resource_address,
                            detail=finding.detail,
                            remediation=finding.remediation,
                        ),
                    }
                ],
            )
            explanations[key] = response.content[0].text.strip()
        except Exception:
            # Never let an API hiccup take down the scan — just fall back
            # to the deterministic remediation text for this one finding.
            continue

    return explanations
