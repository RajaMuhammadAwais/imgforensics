from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from imgforensics.models import Report


def _write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def to_json(report: Report, path: Path) -> None:
    _write(path, json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n")


def terminal(report: Report) -> str:
    lines = [
        f"imgforensics: {report.file.get('original_filename', report.case.get('original_filename', 'unknown'))}",
        f"format={report.file.get('format', report.file.get('magic_format', 'unknown'))} "
        f"size={report.file.get('size_bytes', '?')} bytes sha256={report.hashes.get('sha256', '')}",
        f"findings={len(report.findings)} case_id={report.case.get('case_id', '')}",
    ]
    for finding in report.findings:
        lines.append(
            f"- [{finding.severity.value}] {finding.status.value}: {finding.finding} "
            f"(confidence={finding.confidence:.2f}; method={finding.method})"
        )
    return "\n".join(lines)


def to_html(report: Report, path: Path) -> None:
    data = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    title = html.escape(report.case.get("original_filename", "imgforensics report"))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>imgforensics report — {title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}pre{{background:#f4f6f7;padding:1rem;overflow:auto;border-radius:6px}}.warning{{background:#fff3cd;padding:1rem;border-left:4px solid #d39e00}}</style>
</head><body><h1>imgforensics report</h1><p class="warning">Evidence-oriented analysis aid. Findings are not an authenticity verdict and require contextual review.</p><pre>{html.escape(data)}</pre></body></html>\n"""
    _write(path, page)


def to_sarif(report: Report, path: Path) -> None:
    results: list[dict[str, Any]] = []
    for index, finding in enumerate(report.findings, start=1):
        level = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(finding.severity.value, "note")
        results.append({
            "ruleId": f"imgforensics/{finding.category}/{index}",
            "level": level,
            "message": {"text": finding.finding},
            "properties": {
                "status": finding.status.value,
                "confidence": finding.confidence,
                "method": finding.method,
                "limitations": finding.limitations,
                "evidence": finding.evidence,
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "imgforensics", "version": report.case.get("tool_version", "unknown")}}, "results": results}],
    }
    _write(path, json.dumps(sarif, indent=2, ensure_ascii=False) + "\n")
