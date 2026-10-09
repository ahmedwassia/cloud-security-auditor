"""Render audit results as JSON, Markdown, or an executive HTML report."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape

from cloud_security_auditor.models import AuditResult


def render_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def _markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(result: AuditResult) -> str:
    data = result.to_dict()
    compliance = data["compliance"]
    percentage = (
        f"{compliance['percentage']}%"
        if compliance["percentage"] is not None
        else "Unavailable (collection errors)"
    )
    lines = [
        f"# {result.platform.upper()} Security Audit",
        "",
        f"- **Generated:** {result.generated_at}",
        f"- **Resources scanned:** {result.resources_scanned}",
        f"- **Findings:** {len(result.findings)}",
        f"- **CIS compliance (scoped):** {percentage} "
        f"({compliance['controls_passed']}/{compliance['controls_evaluated']} controls passed)",
        f"- **Benchmark:** {compliance['benchmark']}",
        "",
        f"> {compliance['scope_note']}",
        "",
        "## Findings",
        "",
        "| Severity | Resource | Finding | CIS control | Remediation |",
        "|---|---|---|---|---|",
    ]
    if not result.findings:
        lines.append("| - | - | No findings detected | - | - |")
    for finding in result.findings:
        lines.append(
            "| "
            + " | ".join(
                _markdown_escape(value)
                for value in (
                    finding.severity.value,
                    finding.resource,
                    finding.title,
                    "; ".join(finding.cis_controls) or "Not mapped to a CIS control",
                    finding.remediation,
                )
            )
            + " |"
        )
    if result.errors:
        lines.extend(["", "## Collection errors", ""])
        lines.extend(f"- {_markdown_escape(error)}" for error in result.errors)
    return "\n".join(lines) + "\n"


def render_html(result: AuditResult) -> str:
    template = files("cloud_security_auditor.reporter").joinpath(
        "templates/report.html.j2"
    ).read_text(encoding="utf-8")
    environment = Environment(autoescape=select_autoescape(default=True))
    return environment.from_string(template).render(result=result, data=result.to_dict())


def render_report(result: AuditResult, output_format: str) -> str:
    renderers = {
        "json": render_json,
        "md": render_markdown,
        "markdown": render_markdown,
        "html": render_html,
    }
    try:
        return renderers[output_format.lower()](result)
    except KeyError as exc:
        raise ValueError(
            f"Unsupported report format {output_format!r}; choose json, md, or html"
        ) from exc


def write_report(result: AuditResult, output: str | Path) -> Path:
    path = Path(output)
    formats = {".json": "json", ".md": "md", ".markdown": "markdown", ".html": "html"}
    output_format = formats.get(path.suffix.lower())
    if output_format is None:
        raise ValueError(
            f"Unsupported report extension {path.suffix!r}; use .json, .md, or .html"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(result, output_format), encoding="utf-8")
    return path
