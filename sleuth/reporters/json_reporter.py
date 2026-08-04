"""JSON report output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from ..scanner import Finding


class JsonReporter:
    def report(self, findings: List[Finding], scanned_path: str, output_path: Path | None = None) -> str:
        payload = {
            "tool": "Sleuth",
            "version": "1.0.0",
            "scanned_path": scanned_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

        content = json.dumps(payload, indent=2, ensure_ascii=False)

        if output_path:
            output_path.write_text(content, encoding="utf-8")

        return content
