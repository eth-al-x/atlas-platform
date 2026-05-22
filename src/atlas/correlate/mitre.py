"""
atlas.correlate.mitre
Correlator: MITRE ATT&CK Technique Mapping.

Maps tier flags and recon findings to MITRE ATT&CK technique IDs.
The output speaks the language professional threat reports use — recruiters
at MITRE and security companies recognize ATT&CK references
immediately.

This is a static rules-based mapping, not a probabilistic classifier.
Each rule has the form:
    (predicate over the context) → (list of techniques with rationale)

Pure local computation, no network calls.

References:
    https://attack.mitre.org/techniques/
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from atlas.core.models import CorrelationContext, CorrelationResult
from atlas.correlate.base import Correlator


@dataclass(frozen=True)
class Technique:
    """A single ATT&CK technique reference."""
    tid: str        # e.g. "T1566.002"
    name: str       # e.g. "Spearphishing Link"
    tactic: str     # e.g. "Initial Access"

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.tid,
            "name": self.name,
            "tactic": self.tactic,
            "url": f"https://attack.mitre.org/techniques/{self.tid.replace('.', '/')}",
        }


# ── Technique catalog ─────────────────────────────────────────
# A curated subset of ATT&CK techniques relevant to URL-based threats.
# Add more as needed.

PHISHING_LINK = Technique(
    tid="T1566.002",
    name="Phishing: Spearphishing Link",
    tactic="Initial Access",
)
ACQUIRE_INFRASTRUCTURE_DOMAIN = Technique(
    tid="T1583.001",
    name="Acquire Infrastructure: Domains",
    tactic="Resource Development",
)
DRIVE_BY_COMPROMISE = Technique(
    tid="T1189",
    name="Drive-by Compromise",
    tactic="Initial Access",
)
USER_EXECUTION_LINK = Technique(
    tid="T1204.001",
    name="User Execution: Malicious Link",
    tactic="Execution",
)
COMMAND_SCRIPTING_JS = Technique(
    tid="T1059.007",
    name="Command and Scripting Interpreter: JavaScript",
    tactic="Execution",
)
INGRESS_TOOL_TRANSFER = Technique(
    tid="T1105",
    name="Ingress Tool Transfer",
    tactic="Command and Control",
)
COMPROMISE_INFRASTRUCTURE = Technique(
    tid="T1584",
    name="Compromise Infrastructure",
    tactic="Resource Development",
)


class MitreCorrelator(Correlator):
    name = "mitre"
    display_name = "MITRE ATT&CK Mapping"

    def _correlate(self, context: CorrelationContext) -> CorrelationResult:
        mapped: dict[str, dict[str, Any]] = {}

        for rule in self._rules():
            triggered, rationale = rule(context)
            if not triggered:
                continue
            for technique in triggered:
                existing = mapped.get(technique.tid)
                if existing:
                    existing["rationale"].append(rationale)
                else:
                    mapped[technique.tid] = {
                        **technique.to_dict(),
                        "rationale": [rationale],
                    }

        findings = sorted(mapped.values(), key=lambda f: f["technique_id"])

        if not findings:
            summary = "No ATT&CK techniques mapped"
        elif len(findings) == 1:
            summary = f"1 ATT&CK technique mapped: {findings[0]['technique_id']}"
        else:
            ids = ", ".join(f["technique_id"] for f in findings[:3])
            extra = "" if len(findings) <= 3 else f" (+{len(findings) - 3} more)"
            summary = f"{len(findings)} ATT&CK techniques mapped: {ids}{extra}"

        return CorrelationResult(
            summary=summary,
            findings=findings,
            data={
                "technique_count": len(findings),
                "tactics": sorted({f["tactic"] for f in findings}),
            },
        )

    # ── Rule definitions ──────────────────────────────────────

    def _rules(self) -> list[Callable[[CorrelationContext], tuple[list[Technique], str]]]:
        """
        Each rule returns (triggered_techniques, rationale).
        If the predicate doesn't match, returns ([], "").
        """
        return [
            self._rule_typosquat,
            self._rule_blocklist_or_dnsbl,
            self._rule_virustotal,
            self._rule_urlscan_malicious,
            self._rule_suspicious_javascript,
            self._rule_new_domain_with_flags,
        ]

    @staticmethod
    def _flagged_tier(context: CorrelationContext, name: str) -> bool:
        for tier in context.scan.tier_results:
            if tier.tier_name == name and tier.flagged and not tier.error:
                return True
        return False

    def _rule_typosquat(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        if not self._flagged_tier(context, "typosquat"):
            return [], ""
        return (
            [PHISHING_LINK, ACQUIRE_INFRASTRUCTURE_DOMAIN, USER_EXECUTION_LINK],
            "Typosquat detection: attacker registered a lookalike domain",
        )

    def _rule_blocklist_or_dnsbl(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        if not (
            self._flagged_tier(context, "local_blocklist")
            or self._flagged_tier(context, "dnsbl")
        ):
            return [], ""
        return (
            [PHISHING_LINK, USER_EXECUTION_LINK],
            "Domain appears on threat blocklist or DNSBL",
        )

    def _rule_virustotal(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        if not self._flagged_tier(context, "virustotal"):
            return [], ""
        # VT flagging can indicate multiple delivery modes
        return (
            [PHISHING_LINK, DRIVE_BY_COMPROMISE, INGRESS_TOOL_TRANSFER],
            "VirusTotal multi-engine consensus flagged the URL",
        )

    def _rule_urlscan_malicious(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        urlscan = context.recon.get("urlscan")
        if not urlscan or urlscan.error:
            return [], ""
        if not urlscan.data.get("malicious"):
            return [], ""
        return (
            [PHISHING_LINK, DRIVE_BY_COMPROMISE],
            "urlscan.io sandbox analysis flagged the page as malicious",
        )

    def _rule_suspicious_javascript(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        web = context.recon.get("web_recon")
        if not web or web.error:
            return [], ""
        markers = web.data.get("suspicious_js_markers", 0)
        if isinstance(markers, int) and markers >= 3:
            return (
                [COMMAND_SCRIPTING_JS],
                f"Web recon detected {markers} suspicious JavaScript markers",
            )
        return [], ""

    def _rule_new_domain_with_flags(self, context: CorrelationContext) -> tuple[list[Technique], str]:
        """A very new domain that's also been flagged suggests purpose-built attacker infra."""
        any_flagged = any(
            t.flagged and not t.error for t in context.scan.tier_results
        )
        if not any_flagged:
            return [], ""

        whois = context.recon.get("whois")
        if not whois or whois.error:
            return [], ""

        from datetime import datetime, timezone
        created_raw = whois.data.get("creation_date") or whois.data.get("created")
        if not created_raw:
            return [], ""
        try:
            if isinstance(created_raw, str):
                created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            elif isinstance(created_raw, datetime):
                created = created_raw
            else:
                return [], ""
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
        except (ValueError, TypeError):
            return [], ""

        if age_days <= 30:
            return (
                [ACQUIRE_INFRASTRUCTURE_DOMAIN, COMPROMISE_INFRASTRUCTURE],
                f"Newly-registered domain ({age_days} days old) flagged by analysis",
            )
        return [], ""
