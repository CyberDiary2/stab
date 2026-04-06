"""
Subdomain enumeration via crt.sh and a built-in wordlist.
Used when STAB is run standalone (not fed subdomains from dreakon).
"""
import asyncio

import httpx


async def fetch_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
        )
        if r.status_code == 200:
            return {
                entry["name_value"].lstrip("*.")
                for entry in r.json()
                if domain in entry.get("name_value", "")
            }
    except Exception:
        pass
    return set()


WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
    "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
    "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
    "2tty", "vps", "govyh", "news", "new", "demo", "git", "static",
    "staging", "beta", "preview", "internal", "old", "backup", "docs",
]


async def brute_subdomains(domain: str, client: httpx.AsyncClient) -> set[str]:
    import dns.resolver
    found = set()

    async def check(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, dns.resolver.resolve, fqdn, "A")
            found.add(fqdn)
        except Exception:
            pass

    await asyncio.gather(*[check(w) for w in WORDLIST])
    return found


async def enumerate_subdomains(domain: str) -> list[str]:
    async with httpx.AsyncClient() as client:
        crtsh, brute = await asyncio.gather(
            fetch_crtsh(domain, client),
            brute_subdomains(domain, client),
        )
    return sorted(crtsh | brute)
