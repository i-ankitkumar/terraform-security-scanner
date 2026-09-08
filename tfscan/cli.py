"""Command-line entry point: tfscan <directory>"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from tfscan import __version__
from tfscan.core import render_report, scan
from tfscan.explain import explain_findings

EXIT_CODE_BY_SEVERITY = {"critical": 2, "high": 1, "medium": 0, "low": 0}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfscan",
        description="Static security scanner for Terraform, with optional AI-generated remediation.",
    )
    parser.add_argument("path", help="Directory containing .tf files to scan")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="high",
        help="Exit non-zero if a finding at or above this severity is present (default: high)",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Use ANTHROPIC_API_KEY to generate a tailored explanation per finding",
    )
    parser.add_argument("--version", action="version", version=f"tfscan {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    result = scan(args.path)

    explanations = {}
    if args.explain:
        with console.status("[bold]Asking Claude for tailored remediations...[/bold]"):
            explanations = explain_findings(result.findings)
        if not explanations and result.findings:
            console.print(
                "[dim]No explanations generated — set ANTHROPIC_API_KEY to enable "
                "AI-generated remediation text.[/dim]\n"
            )

    render_report(result, console, explanations)

    if args.fail_on == "never":
        return 0

    threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
    severities_present = {f.severity for f in result.findings}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if any(severity_rank[s] <= threshold for s in severities_present):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
