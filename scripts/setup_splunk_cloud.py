#!/usr/bin/env python
"""
SENTINEL: Autonomous Agentic SOC Commander
setup_splunk_cloud.py — Splunk Cloud trial bootstrap

Automates the parts of "connect SENTINEL to a real Splunk Cloud stack" that
can be done over REST without clicking through Splunk Web:

  1. IP allowlisting for the management port (8089) and HEC (8088) via the
     Admin Config Service (ACS) REST API — required before any REST/HEC
     call from your machine will succeed on a self-service Cloud stack.
  2. Creating the sentinel_* indexes.
  3. Enabling HEC (if not already enabled) and creating a HEC token.
  4. A final connectivity check against /services/server/info.

What this script does NOT do (must be done in Splunk Web — no REST API
exists for these on self-service Cloud stacks):
  - Creating the sentinel_agent role and sentinel_service user
    (Settings -> Roles / Settings -> Users)
  - Creating the sentinel_service auth token
    (Settings -> Tokens -> New Token)
  - Installing the SENTINEL app (requires AppInspect vetting + ACS app
    install — see README for the slim/appinspect/acs commands)

Credentials are never written to disk by this script. After it finishes,
copy the printed values into app/sentinel/local/sentinel.conf.

Usage::

    python scripts/setup_splunk_cloud.py \\
        --stack prd-p-xxxxxxx \\
        --admin-user admin --admin-password '...' \\
        --acs-token '<JWT from Settings -> Tokens>' \\
        --steps allowlist,indexes,hec,verify
"""

from __future__ import annotations

import argparse
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ACS_BASE = "https://admin.splunk.com"

DEFAULT_INDEXES = [
    "sentinel_alerts",
    "sentinel_audit",
    "sentinel_cases",
    "sentinel_metrics",
]


def get_my_ip() -> str:
    resp = requests.get("https://api.ipify.org?format=json", timeout=10)
    resp.raise_for_status()
    return resp.json()["ip"]


def acs_allowlist(stack: str, acs_token: str, subnet: str, feature: str) -> bool:
    """Add `subnet` (CIDR) to the ACS IP allow list for `feature`."""
    url = f"{ACS_BASE}/{stack}/adminconfig/v2/ip-allowlists/{feature}"
    headers = {"Authorization": f"Bearer {acs_token}", "Content-Type": "application/json"}

    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        existing = resp.json().get("subnets", [])
        if subnet in existing:
            print(f"    [{feature}] {subnet} already allowlisted")
            return True
        subnets = existing + [subnet]
    else:
        subnets = [subnet]

    resp = requests.post(url, headers=headers, json={"subnets": subnets}, timeout=30)
    if resp.status_code in (200, 201, 202):
        print(f"    [{feature}] allowlisted {subnet} (ACS may take ~60s to propagate)")
        return True

    print(f"    [{feature}] FAILED ({resp.status_code}): {resp.text[:300]}")
    return False


def enable_hec(stack: str, acs_token: str) -> bool:
    """Enable the HEC feature on the stack via ACS (no-op if already enabled)."""
    url = f"{ACS_BASE}/{stack}/adminconfig/v2/hec/enable"
    headers = {"Authorization": f"Bearer {acs_token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json={}, timeout=30)
    if resp.status_code in (200, 201, 202, 409):  # 409 = already enabled
        print("    HEC enabled (or already was)")
        return True
    print(f"    HEC enable FAILED ({resp.status_code}): {resp.text[:300]}")
    return False


def _splunk_rest(stack: str, admin_user: str, admin_password: str, path: str,
                  method: str = "GET", data=None):
    url = f"https://{stack}.splunkcloud.com:8089{path}"
    return requests.request(
        method, url,
        auth=(admin_user, admin_password),
        data=data,
        params={"output_mode": "json"},
        verify=False,
        timeout=60,
    )


def create_indexes(stack: str, admin_user: str, admin_password: str, indexes) -> None:
    for idx in indexes:
        resp = _splunk_rest(stack, admin_user, admin_password,
                             "/services/data/indexes", method="POST", data={"name": idx})
        if resp.status_code in (200, 201):
            print(f"    [{idx}] created")
        elif resp.status_code == 409:
            print(f"    [{idx}] already exists")
        else:
            print(f"    [{idx}] FAILED ({resp.status_code}): {resp.text[:300]}")


def create_hec_token(stack: str, admin_user: str, admin_password: str,
                      name: str, index: str, sourcetype: str) -> str:
    resp = _splunk_rest(
        stack, admin_user, admin_password,
        "/services/data/inputs/http", method="POST",
        data={"name": name, "index": index, "sourcetype": sourcetype, "indexes": index},
    )
    if resp.status_code not in (200, 201, 409):
        print(f"    HEC token creation FAILED ({resp.status_code}): {resp.text[:300]}")
        return ""

    # Fetch the token value (works whether we just created it or it already existed)
    resp = _splunk_rest(stack, admin_user, admin_password,
                         f"/services/data/inputs/http/{name}", method="GET")
    if resp.status_code != 200:
        print(f"    Could not read back HEC token ({resp.status_code})")
        return ""
    try:
        token = resp.json()["entry"][0]["content"]["token"]
        print(f"    HEC token '{name}' -> index={index}, sourcetype={sourcetype}")
        return token
    except (KeyError, IndexError, ValueError):
        print("    Could not parse HEC token from response")
        return ""


def verify_connectivity(stack: str, admin_user: str, admin_password: str) -> bool:
    resp = _splunk_rest(stack, admin_user, admin_password, "/services/server/info")
    if resp.status_code == 200:
        info = resp.json()["entry"][0]["content"]
        print(f"    OK — {stack}.splunkcloud.com is reachable")
        print(f"    version={info.get('version')} build={info.get('build')}")
        return True
    print(f"    FAILED ({resp.status_code}): {resp.text[:300]}")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap a Splunk Cloud trial for SENTINEL")
    parser.add_argument("--stack", required=True, help="Stack name, e.g. prd-p-xxxxxxx (without .splunkcloud.com)")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--acs-token", default="", help="ACS JWT (Settings -> Tokens). Required for the allowlist/hec-enable steps.")
    parser.add_argument("--my-ip", default="", help="Your public IP/CIDR to allowlist. Auto-detected if omitted.")
    parser.add_argument("--steps", default="allowlist,indexes,hec,verify",
                         help="Comma-separated subset of: allowlist,indexes,hec,verify")
    args = parser.parse_args()

    steps = set(args.steps.split(","))
    sep = "=" * 60
    print(sep)
    print(f"  SENTINEL — Splunk Cloud setup: {args.stack}.splunkcloud.com")
    print(sep)

    if "allowlist" in steps:
        print("\n[1/4] IP allowlist (ACS)")
        if not args.acs_token:
            print("    SKIPPED — pass --acs-token (Settings -> Tokens -> New Token, audience 'admin')")
        else:
            ip = args.my_ip or get_my_ip()
            subnet = ip if "/" in ip else f"{ip}/32"
            print(f"    Allowlisting {subnet} ...")
            acs_allowlist(args.stack, args.acs_token, subnet, "search-api")
            acs_allowlist(args.stack, args.acs_token, subnet, "hec")
            print("    Waiting 60s for ACS changes to propagate ...")
            time.sleep(60)

    if "indexes" in steps:
        print("\n[2/4] Create indexes")
        create_indexes(args.stack, args.admin_user, args.admin_password, DEFAULT_INDEXES)

    hec_token = ""
    if "hec" in steps:
        print("\n[3/4] HEC token")
        if args.acs_token:
            enable_hec(args.stack, args.acs_token)
        hec_token = create_hec_token(
            args.stack, args.admin_user, args.admin_password,
            name="sentinel_hec", index="sentinel_alerts", sourcetype="sentinel:alert",
        )

    if "verify" in steps:
        print("\n[4/4] Connectivity check")
        verify_connectivity(args.stack, args.admin_user, args.admin_password)

    print(f"\n{sep}")
    print("  Next steps:")
    print(f"  - In app/sentinel/local/sentinel.conf, set splunk_host / host =")
    print(f"      {args.stack}.splunkcloud.com")
    if hec_token:
        print(f"  - [hec] token = {hec_token}")
    print("  - Create the sentinel_agent role + sentinel_service user in Splunk Web,")
    print("    then Settings -> Tokens -> New Token to get [splunk] api_token.")
    print(sep)


if __name__ == "__main__":
    main()
