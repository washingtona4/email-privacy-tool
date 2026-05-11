#!/usr/bin/env python3
"""Analyse request body entropy to assess encryption status."""

import argparse
import json
import math
import os

import pandas as pd

PGP_MARKER = "-----BEGIN PGP MESSAGE-----"
PLAINTEXT_THRESHOLD = 4.0
ENCRYPTED_THRESHOLD = 7.0


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def main() -> None:
    parser = argparse.ArgumentParser(description="Check request body encryption status.")
    parser.add_argument("--input", required=True, help="Path to captured CSV file")
    args = parser.parse_args()

    df = pd.read_csv(args.input, dtype=str).fillna("")
    df = df.drop_duplicates(subset=["timestamp", "host", "path"], keep="last")

    per_request: list[dict] = []
    pgp_count = 0
    plaintext_count = 0
    encrypted_count = 0

    for _, row in df.iterrows():
        body = row.get("request_body_snippet", "")
        entropy = shannon_entropy(body)

        is_pgp = PGP_MARKER in body
        if is_pgp:
            label = "pgp_encrypted"
            pgp_count += 1
        elif entropy < PLAINTEXT_THRESHOLD:
            label = "likely_plaintext"
            plaintext_count += 1
        elif entropy >= ENCRYPTED_THRESHOLD:
            label = "likely_encrypted"
            encrypted_count += 1
        else:
            label = "compressed_or_mixed"

        per_request.append(
            {
                "host": row.get("host", ""),
                "path": row.get("path", ""),
                "entropy": round(entropy, 4),
                "classification": label,
            }
        )

    total = len(per_request)
    if pgp_count > 0:
        verdict = "Message content appears end-to-end encrypted via PGP."
    elif encrypted_count > plaintext_count:
        verdict = "Message content appears end-to-end encrypted."
    else:
        verdict = "Message content transmitted without end-to-end encryption."

    result = {
        "per_request": per_request,
        "overall_assessment": {
            "total_requests": total,
            "pgp_encrypted_count": pgp_count,
            "likely_plaintext_count": plaintext_count,
            "likely_encrypted_count": encrypted_count,
            "compressed_or_mixed_count": total - pgp_count - plaintext_count - encrypted_count,
        },
        "pgp_encrypted_count": pgp_count,
        "likely_plaintext_count": plaintext_count,
        "likely_encrypted_count": encrypted_count,
        "verdict": verdict,
    }

    out_dir = os.path.dirname(os.path.abspath(args.input))
    out_path = os.path.join(out_dir, "encryption_analysis.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"PGP encrypted   : {pgp_count}")
    print(f"Likely plaintext: {plaintext_count}")
    print(f"Likely encrypted: {encrypted_count}")
    print(f"Verdict         : {verdict}")
    print(f"Results written to: {out_path}")


if __name__ == "__main__":
    main()
