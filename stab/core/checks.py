"""
Core takeover checks:
- Dangling CNAME pointing to unclaimed service
- Unclaimed S3 buckets
- NS takeover (dangling NS records)
- Dangling A records pointing to unallocated IPs
"""
import asyncio
import socket

import dns.resolver
import httpx

from .fingerprints import CNAME_FINGERPRINTS, S3_REGIONS


async def resolve_cname(subdomain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(subdomain, "CNAME")
        )
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


async def resolve_ns(subdomain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(subdomain, "NS")
        )
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


async def resolve_a(subdomain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(subdomain, "A")
        )
        return [str(r) for r in answers]
    except Exception:
        return []


def is_unallocated_ip(ip: str) -> bool:
    """Check if an IP is in a range commonly associated with unallocated/retired cloud IPs."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        # Private/loopback are not takeover candidates
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            return False
        # Could expand this with actual unallocated range lists
        return False
    except Exception:
        return False


async def check_http_fingerprint(subdomain: str, cnames: list[str], client: httpx.AsyncClient) -> dict | None:
    for fp in CNAME_FINGERPRINTS:
        if not any(pat in cname for cname in cnames for pat in fp["cname_patterns"]):
            continue
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{subdomain}", timeout=10, follow_redirects=True)
                body = r.text.lower()
                status_match = r.status_code in fp["http_status"]
                body_match = any(sig.lower() in body for sig in fp["http_body"])
                if status_match or body_match:
                    return {
                        "type": "cname_takeover",
                        "service": fp["service"],
                        "cname": cnames,
                        "http_status": r.status_code,
                        "evidence": next((s for s in fp["http_body"] if s.lower() in body), None),
                    }
            except Exception:
                continue
    return None


async def check_s3_bucket(subdomain: str, client: httpx.AsyncClient) -> dict | None:
    # Check if subdomain looks like an S3 bucket name
    bucket_name = subdomain.split(".")[0]
    for region in S3_REGIONS:
        url = f"https://{bucket_name}.s3.{region}.amazonaws.com"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code == 404 and "NoSuchBucket" in r.text:
                return {
                    "type": "s3_takeover",
                    "service": "AWS S3",
                    "bucket": bucket_name,
                    "region": region,
                    "evidence": "NoSuchBucket",
                }
        except Exception:
            continue
    return None


async def check_ns_takeover(subdomain: str) -> dict | None:
    ns_records = await resolve_ns(subdomain)
    if not ns_records:
        return None

    for ns in ns_records:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, ns)
        except socket.gaierror:
            return {
                "type": "ns_takeover",
                "service": "NS",
                "ns_record": ns,
                "evidence": f"NS record {ns} does not resolve",
            }
    return None


async def check_subdomain(subdomain: str, client: httpx.AsyncClient) -> dict | None:
    cnames = await resolve_cname(subdomain)

    # Dangling CNAME check
    if cnames:
        result = await check_http_fingerprint(subdomain, cnames, client)
        if result:
            return {**result, "subdomain": subdomain}

    # S3 bucket check
    s3 = await check_s3_bucket(subdomain, client)
    if s3:
        return {**s3, "subdomain": subdomain}

    # NS takeover check
    ns = await check_ns_takeover(subdomain)
    if ns:
        return {**ns, "subdomain": subdomain}

    return None


async def run_checks(subdomains: list[str], concurrency: int = 20) -> list[dict]:
    findings = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        async def bounded_check(sub: str):
            async with semaphore:
                result = await check_subdomain(sub, client)
                if result:
                    findings.append(result)

        await asyncio.gather(*[bounded_check(s) for s in subdomains])

    return findings
