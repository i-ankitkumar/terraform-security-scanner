"""Scan orchestration and report rendering."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from tfscan.parser import TerraformConfig, load_directory
from tfscan.rules import RULES, Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}


@dataclass
class ScanResult:
    config: TerraformConfig
    findings: list[Finding]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def worst_severity(self) -> str | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def scan(path: str) -> ScanResult:
    config = load_directory(path)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(config))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.resource_address))
    return ScanResult(config=config, findings=findings)


def render_report(result: ScanResult, console: Console, explanations: dict[str, str] | None = None) -> None:
    explanations = explanations or {}

    if result.config.parse_errors:
        console.print("[yellow]Parse warnings:[/yellow]")
        for err in result.config.parse_errors:
            console.print(f"  [yellow]![/yellow] {err}")

    console.print(
        f"\nScanned {len(result.config.files_scanned)} file(s), "
        f"{len(result.config.resources)} resource(s).\n"
    )

    if not result.findings:
        console.print("[bold green]No findings. Clean scan.[/bold green]")
        return

    table = Table(show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule")
    table.add_column("Resource")
    table.add_column("Issue")
    table.add_column("AI remediation" if explanations else "Remediation")

    for finding in result.findings:
        key = f"{finding.rule_id}:{finding.resource_address}"
        remediation = explanations.get(key, finding.remediation)
        table.add_row(
            f"[{SEVERITY_COLOR[finding.severity]}]{finding.severity.upper()}[/{SEVERITY_COLOR[finding.severity]}]",
            finding.rule_id,
            f"{finding.resource_address}\n[dim]{finding.file_path}[/dim]",
            finding.title + "\n" + f"[dim]{finding.detail}[/dim]",
            remediation,
        )

    console.print(table)

    counts = {sev: len(result.by_severity(sev)) for sev in SEVERITY_ORDER}
    summary = "  ".join(
        f"[{SEVERITY_COLOR[sev]}]{sev}: {count}[/{SEVERITY_COLOR[sev]}]"
        for sev, count in counts.items()
        if count
    )
    console.print(f"\n{summary}\n")
