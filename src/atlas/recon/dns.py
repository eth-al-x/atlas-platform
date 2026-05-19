"""
atlas.recon.dns
Recon: DNS record lookups for a domain.

Resolves multiple record types in one shot:
    A       -IPv4 addresses
    AAAA    -IPv6 addresses
    MX      -Mail exchange servers
    TXT     -Text records (includes SPF, DKIM, verification tokens)
    NS      -Authoritative name servers

Each record type is queried independently - if one fails, the rest still
return data. This is more informative than the original toolkit's single
A-record lookup using socket.gethostbyname().
"""

from __future__ import annotations

import logging

import dns.resolver

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)


# Record types to query. Add more here (CNAME, SOA, etc.) as needed.
DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "NS")

class DNSReconTool(ReconTool):
    name = "dns"
    display_name = "DNS Lookup"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.record_types = DEFAULT_RECORD_TYPES

        # Reuse the DNSBL tier's timeout setting - sensible default for
        # any DNS query. Could be split into its own config section later.
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.dnsbl.timeout_seconds
        self.resolver.lifetime = config.dnsbl.timeout_seconds

    def _run(self, target: str, **context: object) -> ReconResult:
        records: dict[str, list[str] | dict] = {}

        for record_type in self.record_types:
            records[record_type] = self._query_record(target, record_type)

        # Summary counts make the dashboard/CLI display cleaner
        total_records = sum(
            len(v) for v in records.values() if isinstance(v, list)
        )

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "records": records,
                "total_records": total_records,
                "record_types_queried": list(self.record_types),
            },
        )
    # --- Private Helpers -------------------------------------------------

    def _query_record(self, domain: str, record_type: str) -> list[str] | dict:
        """
        Query a single record type. Returns a list of string values on success,
        or a dict with an error message on failure (so the caller can still render
        meaningful output).
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            values = []

            for answer in answers:
                # MX records have a preference + exchange - format readably
                if record_type == "MX":
                    values.append(f"{answer.preference} {answer.exchange.to_text()}")
                # TXT records come back as lists of byte-strings; join them
                elif record_type == "TXT":
                    parts = [b.decode("utf-8", errors="replace")
                             for b in answer.strings]
                    values.append("".join(parts))
                else:
                    values.append(answer.to_text())

            return sorted(values)

        except dns.resolver.NXDOMAIN:
            return {"error": "domain does not exist"}
        except dns.resolver.NoAnswer:
            # No records of this type - not an error, just absence
            return []
        except dns.resolver.Timeout:
            return {"error": "query timed out"}
        except Exception as exc:
            return {"error": str(exc)}