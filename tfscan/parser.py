"""Load and normalize Terraform (.tf) files into a flat list of resource blocks."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import Any

import hcl2


@dataclass
class Resource:
    """A single Terraform resource block, normalized for rule checks."""

    address: str          # e.g. aws_s3_bucket.data
    type: str              # e.g. aws_s3_bucket
    name: str               # e.g. data
    body: dict[str, Any]     # the raw attribute map for this resource
    file_path: str

    def get(self, key: str, default: Any = None) -> Any:
        value = self.body.get(key, default)
        # hcl2 wraps scalar values in single-element lists; unwrap for convenience.
        if isinstance(value, list) and len(value) == 1:
            return value[0]
        return value


@dataclass
class TerraformConfig:
    """All resources parsed from a directory of Terraform files."""

    resources: list[Resource] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    def of_type(self, *types: str) -> list[Resource]:
        return [r for r in self.resources if r.type in types]


def load_directory(path: str) -> TerraformConfig:
    """Parse every *.tf file under `path` (recursively) into a TerraformConfig."""
    config = TerraformConfig()
    tf_files = sorted(glob.glob(os.path.join(path, "**", "*.tf"), recursive=True))

    for file_path in tf_files:
        config.files_scanned.append(file_path)
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                raw = hcl2.load(fh)
        except Exception as exc:  # malformed HCL shouldn't crash the whole scan
            config.parse_errors.append(f"{file_path}: {exc}")
            continue

        for resource_block in raw.get("resource", []):
            for res_type, named in resource_block.items():
                for res_name, body in named.items():
                    config.resources.append(
                        Resource(
                            address=f"{res_type}.{res_name}",
                            type=res_type,
                            name=res_name,
                            body=body,
                            file_path=file_path,
                        )
                    )

    return config
