"""SARIF 2.1.0 reporter for GitHub Code Scanning / other tools."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from urllib.parse import quote

from ..scanner import Finding


SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


class SarifReporter:
    """Generate SARIF 2.1.0 compliant reports."""

    TOOL_NAME = "Sleuth"
    TOOL_VERSION = "1.0.0"
    TOOL_INFO_URI = "https://github.com/yourusername/sleuth"

    def report(
        self,
        findings: List[Finding],
        scanned_path: str,
        output_path: Path | None = None,
    ) -> str:
        # Build unique rules from findings
        rules_map = {}
        for f in findings:
            if f.rule_id not in rules_map:
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.description},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": f.tags,
                        "security-severity": f.severity,
                    },
                }

        results = []
        for f in findings:
            # SARIF locations are 0-based for columns in some tools,
            # but most (including GitHub) accept 1-based. We use 1-based.
            result = {
                "ruleId": f.rule_id,
                "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                "message": {
                    "text": f"{f.description}: {f.match[:80]}{'...' if len(f.match) > 80 else ''}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": self._to_uri(f.file_path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": f.line_number,
                                "startColumn": max(1, f.start_column),
                                "endColumn": max(1, f.end_column),
                                "snippet": {
                                    "text": f.context or f.match
                                },
                            },
                        }
                    }
                ],
                "properties": {
                    "entropy": f.entropy,
                    "severity": f.severity,
                    "tags": f.tags,
                },
            }
            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_INFO_URI,
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                    "originalUriBaseIds": {
                        "%SRCROOT%": {
                            "uri": self._to_uri(scanned_path) + ("/" if not scanned_path.endswith("/") else "")
                        }
                    },
                }
            ],
        }

        content = json.dumps(sarif, indent=2)

        if output_path:
            output_path.write_text(content, encoding="utf-8")

        return content

    @staticmethod
    def _to_uri(path: str) -> str:
        """Convert a filesystem path to a file URI path component."""
        # Simple normalization for SARIF
        return path.replace("\\", "/")
