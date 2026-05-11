#!/usr/bin/env python3
"""Scan captured traffic for personal data leakage in request bodies."""

import argparse
import json
import os
import re

import pandas as pd

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
DEVICE_ID_LABEL_RE = re.compile(
    r'(?:device_id|client_id|user_id|fingerprint)["\s:=]+([^\s&"\']{4,})',
    re.IGNORECASE,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract metadata / PII from traffic CSV.")
    parser.add_argument("--input", required=True, help="Path to captured CSV file")
    args = parser.parse_args()

    df = pd.read_csv(args.input, dtype=str).fillna("")
    df = df.drop_duplicates(subset=["timestamp", "host", "path"], keep="last")

    email_leaks: list[dict] = []
    device_identifiers: list[dict] = []

    for _, row in df.iterrows():
        body = row.get("request_body_snippet", "")
        host = row.get("host", "")
        path = row.get("path", "")

        # Email addresses
        for match in EMAIL_RE.finditer(body):
            email_leaks.append({"host": host, "path": path, "matched_email": match.group()})

        # UUIDs
        for match in UUID_RE.finditer(body):
            device_identifiers.append(
                {"host": host, "path": path, "matched_string": match.group()}
            )

        # Labeled device/user identifiers
        for match in DEVICE_ID_LABEL_RE.finditer(body):
            device_identifiers.append(
                {"host": host, "path": path, "matched_string": match.group()}
            )

    findings = {
        "email_leaks": email_leaks,
        "device_identifiers": device_identifiers,
        "total_personal_data_exposures": len(email_leaks) + len(device_identifiers),
    }

    out_dir = os.path.dirname(os.path.abspath(args.input))
    out_path = os.path.join(out_dir, "metadata_findings.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Email leaks found       : {len(email_leaks)}")
    print(f"Device identifiers found: {len(device_identifiers)}")
    print(f"Total exposures         : {findings['total_personal_data_exposures']}")
    print(f"Results written to      : {out_path}")


if __name__ == "__main__":
    main()
