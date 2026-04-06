import json
from datetime import datetime
from pathlib import Path


def write_jsonl(findings: list[dict], output_dir: str, domain: str) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"{domain}_{ts}_stab.jsonl"
    with open(path, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")
    return path


def write_report(findings: list[dict], output_dir: str, domain: str) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"{domain}_{ts}_stab_report.md"

    vuln = [f for f in findings if f["type"] in ("cname_takeover", "s3_takeover", "ns_takeover")]
    info = [f for f in findings if f not in vuln]

    with open(path, "w") as f:
        f.write(f"# STAB Report — {domain}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Subdomains scanned:** {len(set(r['subdomain'] for r in findings))}  \n")
        f.write(f"**Takeover candidates:** {len(vuln)}\n\n")

        if vuln:
            f.write("## Takeover Candidates\n\n")
            f.write("| Subdomain | Type | Service | Evidence |\n")
            f.write("|-----------|------|---------|----------|\n")
            for v in sorted(vuln, key=lambda x: x["subdomain"]):
                evidence = v.get("evidence") or v.get("ns_record") or v.get("bucket") or "-"
                f.write(f"| `{v['subdomain']}` | {v['type']} | {v['service']} | {evidence} |\n")
            f.write("\n")

            f.write("## Details\n\n")
            for v in vuln:
                f.write(f"### `{v['subdomain']}`\n\n")
                for k, val in v.items():
                    f.write(f"- **{k}:** {val}\n")
                f.write("\n")
        else:
            f.write("## No takeover candidates found.\n\n")

    return path
