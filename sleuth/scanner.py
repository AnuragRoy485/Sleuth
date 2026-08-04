"""Core scanning engine for Sleuth."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Iterable, List, Optional, Set

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .entropy import shannon_entropy, extract_high_entropy_strings
from .rules import Rule, get_all_rules


# Common binary / non-text extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".db", ".sqlite", ".sqlite3",
}

# Default directories to skip
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "target", "out",
    ".venv", "venv", "env", ".env",
    ".idea", ".vscode", ".vs",
    "coverage", "htmlcov",
    ".tox", ".nox",
}


@dataclass
class Finding:
    """A single secret finding."""
    rule_id: str
    description: str
    severity: str
    file_path: str
    line_number: int
    match: str
    entropy: Optional[float] = None
    context: str = ""  # surrounding lines
    tags: List[str] = field(default_factory=list)
    start_column: int = 0
    end_column: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_number,
            "match": self.match,
            "entropy": round(self.entropy, 3) if self.entropy is not None else None,
            "context": self.context,
            "tags": self.tags,
            "start_column": self.start_column,
            "end_column": self.end_column,
        }


class Scanner:
    """High-performance multi-threaded secrets scanner."""

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        entropy_threshold: float = 4.5,
        enable_entropy: bool = True,
        max_file_size: int = 2 * 1024 * 1024,  # 2 MB
        skip_dirs: Optional[Set[str]] = None,
        skip_extensions: Optional[Set[str]] = None,
        threads: int = 8,
        context_lines: int = 1,
    ):
        self.rules = rules or get_all_rules()
        self.entropy_threshold = entropy_threshold
        self.enable_entropy = enable_entropy
        self.max_file_size = max_file_size
        self.skip_dirs = skip_dirs or DEFAULT_SKIP_DIRS
        self.skip_extensions = skip_extensions or BINARY_EXTENSIONS
        self.threads = max(1, threads)
        self.context_lines = context_lines

        # Pre-compile nothing extra — rules already compile themselves

    def is_binary_or_skip(self, path: Path) -> bool:
        """Quick checks to skip non-text files."""
        if path.suffix.lower() in self.skip_extensions:
            return True
        try:
            size = path.stat().st_size
            if size == 0 or size > self.max_file_size:
                return True
        except OSError:
            return True
        return False

    def should_skip_dir(self, dirname: str) -> bool:
        return dirname in self.skip_dirs or dirname.startswith(".")

    def iter_files(self, root: Path) -> Generator[Path, None, None]:
        """Recursively yield text-like files."""
        if root.is_file():
            if not self.is_binary_or_skip(root):
                yield root
            return

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune directories in-place for efficiency
            dirnames[:] = [d for d in dirnames if not self.should_skip_dir(d)]

            for filename in filenames:
                filepath = Path(dirpath) / filename
                if not self.is_binary_or_skip(filepath):
                    yield filepath

    def _get_context(self, lines: List[str], line_idx: int) -> str:
        """Return a small context window around the finding."""
        start = max(0, line_idx - self.context_lines)
        end = min(len(lines), line_idx + self.context_lines + 1)
        return "".join(lines[start:end]).rstrip()

    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file and return findings."""
        findings: List[Finding] = []

        try:
            # Try utf-8 first, then fallback
            try:
                content = filepath.read_text(encoding="utf-8", errors="strict")
            except UnicodeDecodeError:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return findings

        if not content.strip():
            return findings

        lines = content.splitlines(keepends=True)
        relative_path = str(filepath)

        # 1. Rule-based detection
        for rule in self.rules:
            # Optional keyword pre-filter for speed
            if rule.keywords:
                if not any(kw.lower() in content.lower() for kw in rule.keywords):
                    continue

            for match in rule.pattern.finditer(content):
                matched_text = match.group(0)

                # If rule has entropy requirement, enforce it
                if rule.entropy is not None:
                    ent = shannon_entropy(matched_text)
                    if ent < rule.entropy:
                        continue
                else:
                    ent = shannon_entropy(matched_text)

                # Calculate line number
                start_pos = match.start()
                line_number = content.count("\n", 0, start_pos) + 1
                line_idx = line_number - 1

                # Column
                line_start = content.rfind("\n", 0, start_pos) + 1
                start_col = start_pos - line_start + 1
                end_col = start_col + len(matched_text)

                # Avoid reporting the same match multiple times from overlapping rules
                # (simple dedup by location + match)
                finding = Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    file_path=relative_path,
                    line_number=line_number,
                    match=matched_text[:200],  # truncate very long matches
                    entropy=ent,
                    context=self._get_context(lines, line_idx),
                    tags=rule.tags,
                    start_column=start_col,
                    end_column=end_col,
                )
                findings.append(finding)

        # 2. Generic high-entropy detection (optional)
        if self.enable_entropy:
            for candidate, score, offset in extract_high_entropy_strings(
                content,
                threshold=self.entropy_threshold,
                min_length=20,
                max_length=120,
            ):
                # Skip if already caught by a rule
                if any(candidate in f.match or f.match in candidate for f in findings):
                    continue

                line_number = content.count("\n", 0, offset) + 1
                line_idx = line_number - 1
                line_start = content.rfind("\n", 0, offset) + 1
                start_col = offset - line_start + 1

                findings.append(
                    Finding(
                        rule_id="high-entropy-string",
                        description="High entropy string (possible secret)",
                        severity="MEDIUM",
                        file_path=relative_path,
                        line_number=line_number,
                        match=candidate[:200],
                        entropy=score,
                        context=self._get_context(lines, line_idx),
                        tags=["entropy", "generic"],
                        start_column=start_col,
                        end_column=start_col + len(candidate),
                    )
                )

        return findings

    def scan(
        self,
        path: Path,
        show_progress: bool = True,
    ) -> List[Finding]:
        """
        Scan a file or directory and return all findings.
        Uses a thread pool for performance on large codebases.
        """
        files = list(self.iter_files(path))
        if not files:
            return []

        all_findings: List[Finding] = []

        if show_progress and len(files) > 3:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning files...", total=len(files))

                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_file = {
                        executor.submit(self.scan_file, f): f for f in files
                    }
                    for future in as_completed(future_to_file):
                        findings = future.result()
                        all_findings.extend(findings)
                        progress.advance(task)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = executor.map(self.scan_file, files)
                for findings in results:
                    all_findings.extend(findings)

        # Sort by severity then file
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(
            key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number)
        )

        return all_findings
