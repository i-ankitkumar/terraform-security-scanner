"""Static security/compliance rules for Terraform resources.

Each rule is a small function: (TerraformConfig) -> list[Finding].
Add a new rule by writing a function and registering it in RULES at the
bottom of this file — nothing else needs to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from tfscan.parser import Resource, TerraformConfig

Severity = str  # "critical" | "high" | "medium" | "low"

SECRET_PATTERN = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|aws_secret_access_key|BEGIN (RSA|OPENSSH) PRIVATE KEY|"
    r"password\s*=\s*\"[^\"$]{4,}\")"
)

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis"}


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    resource_address: str
    file_path: str
    detail: str
    remediation: str


RuleFunc = Callable[[TerraformConfig], list[Finding]]


def _cidr_is_open(cidr) -> bool:
    if isinstance(cidr, list):
        return any(_cidr_is_open(c) for c in cidr)
    return cidr in ("0.0.0.0/0", "::/0")


def rule_open_security_group(config: TerraformConfig) -> list[Finding]:
    findings = []
    for res in config.of_type("aws_security_group", "aws_security_group_rule"):
        ingress_blocks = res.get("ingress", [])
        if res.type == "aws_security_group_rule":
            ingress_blocks = [res.body] if res.get("type") == "ingress" else []
        if isinstance(ingress_blocks, dict):
            ingress_blocks = [ingress_blocks]

        for rule in ingress_blocks or []:
            cidrs = rule.get("cidr_blocks", [])
            if not _cidr_is_open(cidrs):
                continue
            from_port = rule.get("from_port")
            from_port = from_port[0] if isinstance(from_port, list) else from_port
            port_name = SENSITIVE_PORTS.get(from_port, f"port {from_port}" if from_port is not None else "all ports")
            severity = "critical" if from_port in SENSITIVE_PORTS or from_port in (None, -1) else "high"
            findings.append(
                Finding(
                    rule_id="TF001",
                    severity=severity,
                    title="Security group open to the internet",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail=f"Ingress rule allows 0.0.0.0/0 on {port_name}.",
                    remediation="Restrict cidr_blocks to known IP ranges (office/VPN CIDR) "
                    "or front the service with a bastion/VPN/load balancer.",
                )
            )
    return findings


def rule_s3_bucket_public(config: TerraformConfig) -> list[Finding]:
    findings = []
    acl_blocks = {r.address: r for r in config.of_type("aws_s3_bucket_acl")}
    for res in config.of_type("aws_s3_bucket"):
        acl = res.get("acl")
        if acl in ("public-read", "public-read-write"):
            findings.append(
                Finding(
                    rule_id="TF002",
                    severity="critical",
                    title="S3 bucket has a public ACL",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail=f'acl = "{acl}" grants anonymous internet access to bucket contents.',
                    remediation="Set acl to \"private\" and, if public content is genuinely required, "
                    "serve it through CloudFront with an origin access control instead.",
                )
            )
    for res in acl_blocks.values():
        acl = res.get("acl")
        if acl in ("public-read", "public-read-write"):
            findings.append(
                Finding(
                    rule_id="TF002",
                    severity="critical",
                    title="S3 bucket ACL resource grants public access",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail=f'aws_s3_bucket_acl.acl = "{acl}".',
                    remediation="Set acl to \"private\" and add an aws_s3_bucket_public_access_block resource.",
                )
            )
    return findings


def rule_s3_bucket_unencrypted(config: TerraformConfig) -> list[Finding]:
    # The `bucket` attribute on the SSE-config resource is usually a reference
    # expression like "${aws_s3_bucket.data.id}" rather than the literal bucket
    # name, so match on the referenced resource's address, not string equality.
    encrypted_refs = {
        str(res.get("bucket")) for res in config.of_type("aws_s3_bucket_server_side_encryption_configuration")
    }
    findings = []
    for res in config.of_type("aws_s3_bucket"):
        is_covered = "server_side_encryption_configuration" in res.body or any(
            res.address in ref or (isinstance(res.get("bucket"), str) and res.get("bucket") in ref)
            for ref in encrypted_refs
        )
        if not is_covered:
            findings.append(
                Finding(
                    rule_id="TF003",
                    severity="medium",
                    title="S3 bucket has no server-side encryption configured",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail="No aws_s3_bucket_server_side_encryption_configuration found for this bucket.",
                    remediation="Add an aws_s3_bucket_server_side_encryption_configuration resource "
                    "using aws:kms or AES256.",
                )
            )
    return findings


def rule_unencrypted_ebs(config: TerraformConfig) -> list[Finding]:
    findings = []
    for res in config.of_type("aws_ebs_volume", "aws_instance"):
        if res.type == "aws_ebs_volume":
            if res.get("encrypted") is not True:
                findings.append(_ebs_finding(res, res.address))
        else:
            for block in res.get("root_block_device", []) or []:
                if isinstance(block, dict) and block.get("encrypted") is not True:
                    findings.append(_ebs_finding(res, f"{res.address}.root_block_device"))
    return findings


def _ebs_finding(res: Resource, address: str) -> Finding:
    return Finding(
        rule_id="TF004",
        severity="high",
        title="EBS volume is not encrypted",
        resource_address=address,
        file_path=res.file_path,
        detail="encrypted is not set to true.",
        remediation="Set encrypted = true (and kms_key_id if you need a customer-managed key).",
    )


def rule_iam_wildcard_policy(config: TerraformConfig) -> list[Finding]:
    findings = []
    for res in config.of_type("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
        policy = res.get("policy")
        if not isinstance(policy, str):
            continue
        normalized = policy.replace(" ", "").replace("'", '"')
        if '"Action":"*"' in normalized:
            findings.append(
                Finding(
                    rule_id="TF005",
                    severity="critical",
                    title="IAM policy grants wildcard Action",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail='Policy document contains "Action": "*", granting unrestricted API access.',
                    remediation="Scope Action to the specific API calls the role actually needs "
                    "(least privilege).",
                )
            )
        if '"Resource":"*"' in normalized:
            findings.append(
                Finding(
                    rule_id="TF006",
                    severity="high",
                    title="IAM policy grants wildcard Resource",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail='Policy document contains "Resource": "*".',
                    remediation="Scope Resource to specific ARNs instead of all resources in the account.",
                )
            )
    return findings


def rule_azure_storage_public(config: TerraformConfig) -> list[Finding]:
    findings = []
    for res in config.of_type("azurerm_storage_account"):
        if res.get("allow_nested_items_to_be_public") is True:
            findings.append(
                Finding(
                    rule_id="TF007",
                    severity="critical",
                    title="Azure storage account allows public blob access",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail="allow_nested_items_to_be_public = true.",
                    remediation="Set allow_nested_items_to_be_public = false and use SAS tokens "
                    "or private endpoints for access instead.",
                )
            )
        if res.get("min_tls_version") not in ("TLS1_2", None) or res.get("min_tls_version") in ("TLS1_0", "TLS1_1"):
            findings.append(
                Finding(
                    rule_id="TF008",
                    severity="medium",
                    title="Azure storage account allows outdated TLS",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail=f"min_tls_version = {res.get('min_tls_version')!r}.",
                    remediation='Set min_tls_version = "TLS1_2".',
                )
            )
        if res.get("https_traffic_only_enabled") is False or res.get("enable_https_traffic_only") is False:
            findings.append(
                Finding(
                    rule_id="TF009",
                    severity="high",
                    title="Azure storage account allows unencrypted HTTP traffic",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail="https_traffic_only_enabled is false.",
                    remediation="Set https_traffic_only_enabled = true.",
                )
            )
    return findings


def rule_azure_nsg_open(config: TerraformConfig) -> list[Finding]:
    findings = []
    for res in config.of_type("azurerm_network_security_rule", "azurerm_network_security_group"):
        rules = [res.body] if res.type == "azurerm_network_security_rule" else (res.get("security_rule", []) or [])
        if isinstance(rules, dict):
            rules = [rules]
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            source = rule.get("source_address_prefix")
            direction = rule.get("direction")
            access = rule.get("access")
            if source in ("*", "0.0.0.0/0", "Internet") and direction == "Inbound" and access == "Allow":
                findings.append(
                    Finding(
                        rule_id="TF010",
                        severity="critical",
                        title="Azure NSG rule allows any inbound traffic from the internet",
                        resource_address=res.address,
                        file_path=res.file_path,
                        detail=f"source_address_prefix = {source!r}, direction = Inbound, access = Allow.",
                        remediation="Scope source_address_prefix to known ranges (VPN/office) "
                        "or use Azure Bastion for management access.",
                    )
                )
    return findings


def rule_hardcoded_secrets(config: TerraformConfig) -> list[Finding]:
    findings = []
    seen_files = set()
    for res in config.resources:
        if res.file_path in seen_files:
            continue
        try:
            with open(res.file_path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        seen_files.add(res.file_path)
        match = SECRET_PATTERN.search(text)
        if match:
            findings.append(
                Finding(
                    rule_id="TF011",
                    severity="critical",
                    title="Possible hardcoded secret in Terraform source",
                    resource_address="(file-level)",
                    file_path=res.file_path,
                    detail=f"Matched pattern: {match.group(0)[:40]}...",
                    remediation="Move secrets to a secret manager (AWS Secrets Manager, Azure Key Vault) "
                    "or environment-backed variables, never literal values in .tf files.",
                )
            )
    return findings


def rule_missing_tags(config: TerraformConfig) -> list[Finding]:
    """Compliance rule: taggable resources should carry ownership/cost-center tags."""
    taggable_types = (
        "aws_instance",
        "aws_s3_bucket",
        "aws_db_instance",
        "azurerm_storage_account",
        "azurerm_virtual_machine",
        "azurerm_resource_group",
    )
    findings = []
    for res in config.of_type(*taggable_types):
        tags = res.get("tags")
        if not tags:
            findings.append(
                Finding(
                    rule_id="TF012",
                    severity="low",
                    title="Resource is missing tags",
                    resource_address=res.address,
                    file_path=res.file_path,
                    detail="No tags block found — cost allocation and ownership tracking will break.",
                    remediation='Add a tags = { Owner = "...", CostCenter = "...", Environment = "..." } block.',
                )
            )
    return findings


def rule_unpinned_provider(config: TerraformConfig) -> list[Finding]:
    findings = []
    seen_files = set()
    for res in config.resources:
        if res.file_path in seen_files:
            continue
        seen_files.add(res.file_path)
        try:
            with open(res.file_path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        if "required_providers" in text and re.search(r'version\s*=\s*"[~<>=\s\d.]*\*"', text):
            findings.append(
                Finding(
                    rule_id="TF013",
                    severity="low",
                    title="Provider version constraint is unpinned",
                    resource_address="(file-level)",
                    file_path=res.file_path,
                    detail="A provider version constraint resolves to any version (wildcard).",
                    remediation='Pin a version range, e.g. version = "~> 5.0", to keep applies reproducible.',
                )
            )
    return findings


RULES: list[RuleFunc] = [
    rule_open_security_group,
    rule_s3_bucket_public,
    rule_s3_bucket_unencrypted,
    rule_unencrypted_ebs,
    rule_iam_wildcard_policy,
    rule_azure_storage_public,
    rule_azure_nsg_open,
    rule_hardcoded_secrets,
    rule_missing_tags,
    rule_unpinned_provider,
]
