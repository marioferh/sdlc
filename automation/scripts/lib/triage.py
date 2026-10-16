"""Assisted CVE triage suggestions."""

from __future__ import annotations

from .policy import age_hours, sla_breached, sla_hours_for


def suggest(item: dict) -> dict:
    sev = str(item.get("severity", "UNKNOWN")).upper()
    pkg = (item.get("package") or "").strip()
    repo = (item.get("repository") or "").strip()
    age = age_hours(item)
    breached = sla_breached(item)
    sla = sla_hours_for(sev)

    reasons: list[str] = []
    action = "mitigate"
    confidence = "medium"

    if not repo and not pkg:
        action = "discard"
        confidence = "low"
        reasons.append("No package/repository linked — likely false positive or incomplete intake.")
    elif sev == "CRITICAL":
        action = "fix"
        confidence = "high"
        reasons.append("CRITICAL severity should be remediated, not accepted.")
    elif sev == "HIGH":
        action = "fix"
        confidence = "high"
        reasons.append("HIGH severity: prefer upgrade / patch.")
    elif sev == "MEDIUM":
        action = "mitigate"
        confidence = "medium"
        reasons.append("MEDIUM: schedule mitigation; accept only with expiry if blocked.")
    elif sev == "LOW":
        action = "accept"
        confidence = "medium"
        reasons.append("LOW: candidate for time-bounded accept-risk if not exploitable.")
    else:
        action = "mitigate"
        confidence = "low"
        reasons.append("Unknown severity — gather more context before deciding.")

    if breached:
        reasons.append(f"SLA breached (limit {sla}h, age ~{int(age or 0)}h). Escalate.")
        if action == "accept":
            action = "fix"
            confidence = "high"

    if pkg and repo and action == "fix":
        reasons.append(f"Plan: bump `{pkg}` in `{repo}`, open PR, run CI, mark fixed.")

    checklist = {
        "fix": [
            "Identify fixed version / advisory",
            f"Upgrade {pkg or 'package'} in {repo or 'repo'}",
            "Open PR and link this CVE",
            "Run CI / security tests",
            "Merge and deploy",
            "cve_manage.py fix <CVE> --pr <url>",
        ],
        "mitigate": [
            "Confirm reachability / exploit path",
            "Apply compensating control if needed",
            "Schedule upgrade window",
            "Re-triage after mitigation",
        ],
        "accept": [
            "Document business justification",
            "Get approver (four-eyes if CRITICAL)",
            "cve_manage.py accept <CVE> --reason '...' --expires-days N --approver ...",
            "Calendar reminder before expiry",
        ],
        "discard": [
            "Confirm not present in SBOM / runtime",
            "cve_manage.py discard <CVE> --reason '...'",
        ],
    }

    return {
        "id": item.get("id"),
        "severity": sev,
        "suggestion": action,
        "confidence": confidence,
        "sla_hours": sla,
        "age_hours": round(age, 1) if age is not None else None,
        "sla_breached": breached,
        "reasons": reasons,
        "checklist": checklist.get(action, []),
    }
