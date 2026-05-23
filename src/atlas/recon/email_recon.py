"""
atlas.recon.email_recon
Recon: Email infrastructure & anti-spoofing posture.

Queries every relevant DNS record for a domain's mail setup and parses the
policies into structured data plus a 0–100 posture score:

    MX     — does mail land somewhere?
    SPF    — which servers may send on behalf of the domain? (TXT @ apex)
    DMARC  — what should receivers do when SPF/DKIM fail? (TXT @ _dmarc)
    DKIM   — is there a publishing key? (TXT @ <selector>._domainkey)

Why this matters: most phishing landing pages don't bother configuring
mail. A domain that *looks* like a major brand but has no MX, no SPF, or
DMARC `p=none` is overwhelmingly more likely to be a phishing lander
than a real corporate domain. Conversely, every legitimate brand has all
four configured in some form.

DKIM is special: there's no DNS way to enumerate selectors, so we probe
a curated list of common ones (`default`, `google`, `mail`, `selector1`,
`selector2`, `k1`, `mxvault`, …). A "no DKIM" result here means *we
couldn't find a published key under these common selectors* — not
"definitely no DKIM."
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

import dns.resolver

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)


# DKIM selectors we'll probe. Curated from real-world prevalence:
# google/k1 (Google Workspace), selector1/selector2 (Microsoft 365 / Outlook),
# mandrill (Mailchimp Transactional), s1/s2/s1024 (generic numbered).
COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "mail", "smtp", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "s1024",
    "dkim", "mandrill", "mxvault", "key1", "key2",
)


# SPF qualifier → human label. The qualifier on the terminal `all` mechanism
# is what actually enforces the policy.
SPF_QUALIFIER_LABELS: dict[str, str] = {
    "+": "pass",       # +all means "allow everything" — basically no policy
    "-": "fail",       # -all means "reject anything not listed" — strict
    "~": "softfail",   # ~all means "mark as suspect but accept" — common compromise
    "?": "neutral",    # ?all means "no opinion" — equivalent to no SPF
}


class EmailReconTool(ReconTool):
    name = "email_recon"
    display_name = "Email Infrastructure"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.dnsbl.timeout_seconds
        self.resolver.lifetime = config.dnsbl.timeout_seconds

    def _run(self, target: str, **context: object) -> ReconResult:
        mx = self._query_mx(target)
        spf = self._query_spf(target)
        dmarc = self._query_dmarc(target)
        dkim = self._query_dkim(target)
        posture = self._score_posture(mx, spf, dmarc, dkim)

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "domain": target,
                "mx": mx,
                "spf": spf,
                "dmarc": dmarc,
                "dkim": dkim,
                "posture": posture,
            },
        )

    # ── MX ─────────────────────────────────────────────────────

    def _query_mx(self, domain: str) -> dict:
        """
        Return MX records sorted by preference (lowest = most-preferred).
        An empty list is meaningful — a domain with NO MX cannot receive
        mail at all, which is a strong "this isn't a real organization"
        signal when the domain otherwise impersonates a brand.
        """
        try:
            answers = self.resolver.resolve(domain, "MX")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"has_mx": False, "records": []}
        except dns.exception.DNSException as exc:
            return {"has_mx": False, "records": [], "error": str(exc)}

        records = sorted(
            ({"preference": rr.preference, "exchange": str(rr.exchange)} for rr in answers),
            key=lambda r: r["preference"],
        )
        return {"has_mx": bool(records), "records": records}

    # ── SPF ────────────────────────────────────────────────────

    def _query_spf(self, domain: str) -> dict:
        """
        SPF lives in a TXT record at the apex domain starting with `v=spf1`.
        A domain may legally have only ONE SPF record (RFC 7208). If there
        are multiple v=spf1 records we surface them all but flag it.
        """
        spf_records = [
            txt for txt in self._all_txt(domain)
            if txt.lower().startswith("v=spf1")
        ]

        if not spf_records:
            return {"has_spf": False, "record": None, "policy": "none"}

        record = spf_records[0]
        mechanisms = record.split()[1:]  # drop "v=spf1"

        # The final mechanism controls enforcement. Strict policies end in `-all`.
        policy = "neutral"  # default if no terminal `all`
        for mech in reversed(mechanisms):
            stripped = mech.lower().lstrip("+-~?")
            if stripped == "all":
                qualifier = mech[0] if mech[0] in "+-~?" else "+"
                policy = SPF_QUALIFIER_LABELS.get(qualifier, "neutral")
                break

        out = {
            "has_spf": True,
            "record": record,
            "policy": policy,
            "mechanisms": mechanisms,
        }
        if len(spf_records) > 1:
            # Multiple SPF records make a domain technically misconfigured
            # — receivers treat this as PermError per RFC.
            out["multiple_records"] = len(spf_records)
        return out

    # ── DMARC ──────────────────────────────────────────────────

    DMARC_TAG_RE = re.compile(r"\s*([a-zA-Z]+)\s*=\s*([^;]*)")

    def _query_dmarc(self, domain: str) -> dict:
        """
        DMARC is a TXT record at `_dmarc.<domain>` starting with `v=DMARC1`.
        The policy is `p=`; subdomain policy is `sp=` (defaults to p if
        absent). `pct=` controls what percentage of mail is subject to the
        policy (default 100). All matter for spoofing risk.
        """
        try:
            txts = self._all_txt(f"_dmarc.{domain}")
        except Exception:
            txts = []

        dmarc_records = [t for t in txts if t.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            return {"has_dmarc": False, "record": None, "policy": None}

        record = dmarc_records[0]
        tags = dict(self.DMARC_TAG_RE.findall(record))

        policy = (tags.get("p") or "").lower().strip() or None
        sub_policy = (tags.get("sp") or "").lower().strip() or None
        pct_str = tags.get("pct", "100").strip()
        try:
            pct = int(pct_str)
        except (TypeError, ValueError):
            pct = 100

        return {
            "has_dmarc": True,
            "record": record,
            "policy": policy,                                     # "none" / "quarantine" / "reject"
            "subdomain_policy": sub_policy,
            "pct": pct,
            "reporting_uri_aggregate": (tags.get("rua") or "").strip() or None,
            "reporting_uri_forensic":  (tags.get("ruf") or "").strip() or None,
        }

    # ── DKIM ───────────────────────────────────────────────────

    def _query_dkim(self, domain: str) -> dict:
        """
        Probe known DKIM selectors and report which ones publish a key.
        An empty result means "no DKIM under common selectors" — not
        definitive proof that no DKIM exists (custom selectors aren't
        enumerable via DNS).
        """
        found: list[str] = []
        for selector in COMMON_DKIM_SELECTORS:
            host = f"{selector}._domainkey.{domain}"
            txts = self._all_txt(host)
            # A DKIM record contains `k=` and `p=` at minimum
            if any(("p=" in t and "k=" in t.lower()) or "v=DKIM1" in t for t in txts):
                found.append(selector)

        return {
            "has_dkim": bool(found),
            "selectors_found": found,
            "selectors_probed": list(COMMON_DKIM_SELECTORS),
        }

    # ── Posture score ─────────────────────────────────────────

    def _score_posture(
        self,
        mx: dict,
        spf: dict,
        dmarc: dict,
        dkim: dict,
    ) -> dict:
        """
        Compute a 0–100 posture score and a categorical level.

        Component weights (target ≈ 100 max):
            MX present:                30
            SPF present:                15
              + SPF -all (strict):     +10
              + SPF ~all (soft):        +5
            DMARC present:              20
              + p=quarantine:          +10
              + p=reject:              +20  (and pct=100: full credit)
            DKIM (any common selector):  5
        """
        score = 0
        issues: list[str] = []

        # ── MX ────────────────────────────────────────────────
        if mx.get("has_mx"):
            score += 30
        else:
            issues.append("No MX records — domain cannot receive mail")

        # ── SPF ───────────────────────────────────────────────
        if spf.get("has_spf"):
            score += 15
            policy = spf.get("policy")
            if policy == "fail":
                score += 10                    # -all : strict
            elif policy == "softfail":
                score += 5                     # ~all : soft
                issues.append("SPF uses `~all` (softfail) — receivers may still deliver spoofed mail")
            elif policy in ("neutral", "pass"):
                issues.append(f"SPF policy `{policy}` provides no real spoofing protection")
            if spf.get("multiple_records"):
                issues.append(f"Multiple SPF records present ({spf['multiple_records']}) — RFC 7208 violation")
        else:
            issues.append("No SPF record — anyone can claim to send mail as this domain")

        # ── DMARC ─────────────────────────────────────────────
        if dmarc.get("has_dmarc"):
            score += 20
            policy = dmarc.get("policy")
            pct = dmarc.get("pct") or 100
            if policy == "quarantine":
                score += int(10 * pct / 100)
                if pct < 100:
                    issues.append(f"DMARC quarantines only {pct}% of failing mail")
            elif policy == "reject":
                score += int(20 * pct / 100)
                if pct < 100:
                    issues.append(f"DMARC rejects only {pct}% of failing mail")
            elif policy == "none":
                issues.append("DMARC policy is `p=none` (monitoring only, does not enforce)")
            elif policy is None:
                issues.append("DMARC record is missing the `p=` policy tag")
        else:
            issues.append("No DMARC record — no receiver-side spoofing enforcement")

        # ── DKIM ──────────────────────────────────────────────
        if dkim.get("has_dkim"):
            score += 5
        else:
            issues.append("No DKIM key under common selectors (custom selectors not enumerable)")

        score = max(0, min(100, score))

        # Categorical bucket
        if score >= 91:
            level = "strict"
        elif score >= 66:
            level = "strong"
        elif score >= 41:
            level = "partial"
        elif score >= 16:
            level = "minimal"
        else:
            level = "none"

        return {
            "score": score,
            "level": level,
            "issues": issues,
        }

    # ── Helpers ───────────────────────────────────────────────

    def _all_txt(self, name: str) -> list[str]:
        """
        Return every TXT record at a name, joining chunked strings per record.
        Resolver errors return an empty list (caller decides what's meaningful).
        """
        try:
            answers = self.resolver.resolve(name, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException as exc:
            logger.debug("TXT lookup failed for %s: %s", name, exc)
            return []

        results: list[str] = []
        for rr in answers:
            # Each rr.strings is a tuple of bytes; concat without separator
            # because DNS-level chunking is purely transport, not semantic.
            joined = b"".join(s for s in rr.strings).decode("utf-8", errors="replace")
            results.append(joined)
        return results
