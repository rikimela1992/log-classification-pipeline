"""Summaries that turn validated predictions into a reviewable report."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .taxonomy import SUBSYSTEM_LABELS

ATTENTION_SEVERITIES = ("security_event", "error", "warning")
SEVERITY_ORDER = (*ATTENTION_SEVERITIES, "info", "routine")
DEFAULT_ATTENTION_LIMIT = 200

_VOLATILE_TOKEN = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b|\d+",
    re.IGNORECASE,
)


def summarize_predictions(
    predictions: Sequence[Mapping[str, Any]],
    *,
    attention_limit: int = DEFAULT_ATTENTION_LIMIT,
) -> dict[str, Any]:
    """Count predictions and list the records that deserve human review."""

    if attention_limit < 1:
        raise ValueError("attention_limit must be positive")
    severity = Counter(item["severity"]["label"] for item in predictions)
    subsystem = Counter(item["subsystem"]["label"] for item in predictions)
    ranked = sorted(
        (
            (SEVERITY_ORDER.index(item["severity"]["label"]), record, item)
            for record, item in enumerate(predictions, start=1)
            if item["severity"]["label"] in ATTENTION_SEVERITIES
        ),
        key=lambda entry: entry[:2],
    )
    return {
        "records": len(predictions),
        "abstained": sum(1 for item in predictions if item["abstained"]),
        "severity": {label: severity[label] for label in SEVERITY_ORDER},
        "subsystem": [
            {"label": label, "count": subsystem[label]}
            for label in sorted(SUBSYSTEM_LABELS, key=lambda name: (-subsystem[name], name))
            if subsystem[label]
        ],
        "attention_total": len(ranked),
        "attention": [
            {
                "record": record,
                "severity": item["severity"]["label"],
                "subsystem": item["subsystem"]["label"],
                "abstained": item["abstained"],
            }
            for _rank, record, item in ranked[:attention_limit]
        ],
    }


def group_findings(
    records: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Collapse repeated attention records into patterns, worst first."""

    if len(records) != len(predictions):
        raise ValueError("input and prediction record counts differ")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for number, (record, prediction) in enumerate(zip(records, predictions), start=1):
        severity = prediction["severity"]["label"]
        if severity not in ATTENTION_SEVERITIES:
            continue
        message = str(record["message"])
        pattern = _VOLATILE_TOKEN.sub("#", message)
        group = groups.setdefault(
            (severity, pattern),
            {
                "severity": severity,
                "subsystem": prediction["subsystem"]["label"],
                "count": 0,
                "first_record": number,
                "example": message,
            },
        )
        group["count"] += 1
    ordered = sorted(
        groups.values(),
        key=lambda item: (
            SEVERITY_ORDER.index(item["severity"]),
            -item["count"],
            item["first_record"],
        ),
    )
    return ordered[:limit]


def render_text_report(
    summary: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> str:
    """Render a terminal report; messages come from the caller's own input."""

    lines = [f"Records: {summary['records']}   Abstained: {summary['abstained']}", ""]
    for label in SEVERITY_ORDER:
        lines.append(f"{label:<15}{summary['severity'][label]:>8}")
    lines.append("")
    lines.append(
        "Subsystems: "
        + ", ".join(f"{item['label']} {item['count']}" for item in summary["subsystem"])
    )
    lines.append("")
    if not findings:
        lines.append("Nothing needs attention.")
    else:
        lines.append(f"Needs attention ({summary['attention_total']} records):")
        for item in findings:
            lines.append(
                f"  {item['count']:>6} x {item['severity']:<15}{item['subsystem']:<10}"
                f"record {item['first_record']}: {item['example'][:160]}"
            )
    return "\n".join(lines)

