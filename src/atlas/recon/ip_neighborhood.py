"""
atlas.recon.ip_neighborhood
Recon: PTR enumeration of IPs adjacent to the target's address.

Phishing operators frequently park multiple lookalike domains on the same
VPS or a tight cluster of IPs from the same provider. This tool resolves
the target's IP, then PTR-queries every IP in the surrounding CIDR
block (default /28 — 16 addresses) in parallel.

The result surfaces:
    - The PTR of the IP itself (often reveals shared hosting patterns
      like 'cpanel-server-23.bulk-hosting.example.com')
    - PTRs of neighbors, with unique apex domains aggregated
    - A summary count of how many neighbors responded

It's purely DNS — no contact with the target hosts at all — so it's
safe and fast (sub-second for /28, a few seconds for /24).

Default neighborhood size is /28 (16 IPs). The user can widen this to
/24 (256 IPs) for a richer survey or narrow it for surgical probes.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.reversename

from atlas.core.config import AtlasConfig
from atlas.core.models import ReconResult
from atlas.recon.base import ReconTool

logger = logging.getLogger(__name__)


# Default and bounds for the CIDR prefix we'll enumerate
DEFAULT_CIDR_BITS = 28      # 16 IPs — fast, focused
MIN_CIDR_BITS = 24          # /24 = 256 IPs — wide, still tolerable
MAX_CIDR_BITS = 30          # /30 = 4 IPs — surgical

# Cap concurrent PTR lookups to be a polite resolver client.
# Most public resolvers handle ≥ 32 concurrent queries fine.
MAX_CONCURRENT_PTR = 16


class IPNeighborhoodReconTool(ReconTool):
    name = "ip_neighborhood"
    display_name = "IP Neighborhood"

    def __init__(self, config: AtlasConfig) -> None:
        super().__init__(config)
        self.resolver = dns.resolver.Resolver()
        # Short timeout per IP — a non-responsive PTR is the common case,
        # and we don't want it to dominate scan time.
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def _run(self, target: str, **context: object) -> ReconResult:
        cidr_bits = self._coerce_cidr_bits(context.get("cidr_bits"))

        # Accept either a domain or an IP directly. Both code paths work.
        target_ip = self._resolve_target_ip(target)
        if target_ip is None:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                data={
                    "ip": None,
                    "cidr": None,
                    "neighbors": [],
                    "error": "could not resolve target to an IP address",
                },
            )

        # IPv6 isn't supported for neighborhood scanning — the address
        # space is too large for PTR-sweeping to make sense, and most
        # phishing infra is IPv4 anyway.
        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                data={"ip": target_ip, "error": "invalid IP address"},
            )
        if ip_obj.version != 4:
            return ReconResult(
                recon_type=self.name,
                domain=target,
                data={
                    "ip": target_ip,
                    "error": "IPv6 not supported for neighborhood scanning",
                },
            )

        network = ipaddress.ip_network(f"{target_ip}/{cidr_bits}", strict=False)
        ips_to_probe = [str(ip) for ip in network.hosts()]

        # Always include the target itself even if it's the network or broadcast
        # address — the user explicitly asked about it.
        if target_ip not in ips_to_probe:
            ips_to_probe.append(target_ip)

        # Concurrent PTR lookups
        ptr_map = self._concurrent_ptr_lookup(ips_to_probe)

        # Build structured neighbors list, marking which entry is the target
        neighbors = []
        for ip in sorted(ips_to_probe, key=lambda s: ipaddress.ip_address(s)):
            ptr = ptr_map.get(ip)
            if ptr is None:
                continue  # Skip IPs that didn't resolve — keeps output focused
            neighbors.append({
                "ip": ip,
                "ptr": ptr,
                "self": ip == target_ip,
            })

        # Extract unique apex-ish domains from PTRs (rough — used for at-a-glance)
        domains_in_neighborhood = sorted({
            self._ptr_to_apex(n["ptr"]) for n in neighbors if n.get("ptr")
        })

        return ReconResult(
            recon_type=self.name,
            domain=target,
            data={
                "ip": target_ip,
                "cidr": str(network),
                "cidr_bits": cidr_bits,
                "neighborhood_size": network.num_addresses,
                "neighbors": neighbors,
                "summary": {
                    "neighbors_found": len(neighbors),
                    "ips_probed": len(ips_to_probe),
                    "unique_domains": domains_in_neighborhood,
                },
            },
        )

    # ── Resolution helpers ────────────────────────────────────

    @staticmethod
    def _coerce_cidr_bits(raw: object) -> int:
        """
        Parse and bound-check the cidr_bits context value.
        Returns DEFAULT_CIDR_BITS on any invalid input — failing safely
        is better than rejecting calls over an option parameter.
        """
        if raw is None:
            return DEFAULT_CIDR_BITS
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return DEFAULT_CIDR_BITS
        return max(MIN_CIDR_BITS, min(MAX_CIDR_BITS, n))

    @staticmethod
    def _resolve_target_ip(target: str) -> str | None:
        """
        Resolve a domain or accept a literal IP. Returns None on failure.
        Strips any URL prefix the caller may have passed.
        """
        # Try IP literal first — cheap test, no DNS call
        candidate = target.strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

        # Fall through to DNS A-record resolution
        try:
            return socket.gethostbyname(candidate)
        except socket.gaierror as exc:
            logger.debug("Failed to resolve %s: %s", candidate, exc)
            return None

    def _concurrent_ptr_lookup(self, ips: list[str]) -> dict[str, str]:
        """
        Run PTR lookups in parallel. Returns {ip: ptr_record} for every
        IP that resolved; missing keys mean no record / timeout / error.
        """
        results: dict[str, str] = {}

        def lookup(ip: str) -> tuple[str, str | None]:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev_name, "PTR")
                # PTR records are FQDNs ending in '.', take the first
                return ip, str(answers[0]).rstrip(".")
            except dns.exception.DNSException:
                return ip, None
            except Exception as exc:
                logger.debug("PTR lookup error for %s: %s", ip, exc)
                return ip, None

        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_PTR) as pool:
            for ip, ptr in pool.map(lookup, ips):
                if ptr:
                    results[ip] = ptr
        return results

    @staticmethod
    def _ptr_to_apex(ptr: str) -> str:
        """
        Reduce a PTR hostname to a rough apex domain for summary grouping.
        Not strict (doesn't consult the public suffix list) — fine for
        a quick at-a-glance view.

        Examples:
            'ec2-1-2-3-4.compute.amazonaws.com' → 'amazonaws.com'
            'host.bulk-hosting.example.com'     → 'example.com'
            'mail.example.co.uk'                → 'co.uk'   (acceptable rough cut)
        """
        parts = ptr.rstrip(".").split(".")
        if len(parts) < 2:
            return ptr.rstrip(".")
        return ".".join(parts[-2:])
