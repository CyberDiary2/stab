# STAB - Subdomain Takeover And Brute-force

drew's subdomain takeover scanner. finds dangling CNAMEs, unclaimed S3 buckets, and NS takeovers across a target domain.

## what it does

1. **subdomain enumeration** - passive discovery via crt.sh + DNS brute force against a built-in wordlist
2. **CNAME takeover detection** - resolves CNAME records and checks HTTP responses against fingerprints for 15+ services
3. **S3 bucket takeover** - checks if subdomains point to unclaimed S3 buckets across all major AWS regions
4. **NS takeover detection** - finds NS records pointing to nameservers that no longer resolve
5. **output** - JSONL results + markdown report

### services fingerprinted

GitHub Pages, Heroku, Netlify, AWS S3, Fastly, Shopify, Tumblr, WordPress, Surge.sh, Zendesk, HubSpot, Azure, Vercel, Cargo, Fly.io

---

## install

```bash
git clone git@github.com:CyberDiary2/stab.git
cd stab
python -m venv venv
source venv/bin/activate
pip install -e .
```

---

## usage

```bash
# scan a domain (enumerates subdomains automatically)
stab scan example.com

# save results to a folder
stab scan example.com --output ./results

# skip enumeration, use your own subdomain list
stab scan example.com -i subdomains.txt --no-enumerate

# pipe subdomains from another tool
cat subdomains.txt | stab scan example.com -i -

# pipe from dreakon
cat dreakon_results.jsonl | jq -r '.url' | stab scan example.com -i -

# adjust concurrency (default 20)
stab scan example.com --concurrency 50
```

---

## output files

```
results/
├── example.com_20260101_120000_stab.jsonl
└── example.com_20260101_120000_stab_report.md
```

- `stab.jsonl` - one finding per line, compatible with nuclei/burp
- `stab_report.md` - markdown report with summary table and full details per finding

### example finding

```json
{
  "type": "cname_takeover",
  "service": "GitHub Pages",
  "subdomain": "blog.example.com",
  "cname": ["exampleorg.github.io"],
  "http_status": 404,
  "evidence": "There isn't a GitHub Pages site here"
}
```

### finding types

| type | description |
|------|-------------|
| `cname_takeover` | CNAME points to an unclaimed service |
| `s3_takeover` | subdomain references a non-existent S3 bucket |
| `ns_takeover` | NS record points to a nameserver that doesn't resolve |

---

## also built into dreakon

STAB runs automatically as phase 6 when using dreakon:

```bash
dreakon scan example.com                  # runs all phases including takeover
dreakon scan example.com --no-takeover    # skip phase 6
dreakon scan example.com --interactive    # checkbox to pick phases
```

When run inside dreakon, STAB reuses dreakon's already-enumerated subdomains instead of re-enumerating from scratch.
