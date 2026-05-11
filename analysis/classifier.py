#!/usr/bin/env python3
"""Classify captured traffic by domain category."""

import argparse
import json
import os
import re

import pandas as pd
import yaml
from rich.console import Console
from rich.table import Table

CDN_DOMAINS = {"fastly.net", "cloudflare.com", "akamaized.net", "cloudfront.net"}
DISCONNECT_CATEGORIES = {"Advertising", "Analytics", "Social", "Fingerprinting"}


def load_providers(config_path: str) -> dict:
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_disconnect(path: str) -> dict[str, str]:
    """Return domain -> category mapping from disconnect.json."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    domain_to_category: dict[str, str] = {}
    for category, entities in data.get("categories", {}).items():
        if category not in DISCONNECT_CATEGORIES:
            continue
        for entity in entities:
            for _name, domains in entity.items():
                if isinstance(domains, list):
                    for d in domains:
                        domain_to_category[d.lower()] = category.lower()
                elif isinstance(domains, dict):
                    for d in domains:
                        domain_to_category[d.lower()] = category.lower()
    return domain_to_category


def load_easyprivacy(path: str) -> set[str]:
    """Return set of tracker domains extracted from EasyPrivacy list."""
    domains: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("||"):
                # Strip leading || and trailing ^
                domain = line[2:].split("^")[0].split("/")[0].lower()
                if domain:
                    domains.add(domain)
    return domains


def host_matches(host: str, domains: list[str]) -> bool:
    host = host.lower().lstrip("www.")
    for d in domains:
        if host == d or host.endswith("." + d):
            return True
    return False


def host_matches_set(host: str, domain_set: set[str]) -> bool:
    host = host.lower().lstrip("www.")
    parts = host.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in domain_set:
            return True
    return False


def classify_host(
    host: str,
    first_party: list[str],
    disconnect_map: dict[str, str],
    easyprivacy: set[str],
) -> str:
    if host_matches(host, first_party):
        return "first_party"

    cat = None
    h = host.lower().lstrip("www.")
    parts = h.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in disconnect_map:
            cat = disconnect_map[candidate]
            break

    if cat:
        return cat  # advertising / analytics / social / fingerprinting

    if host_matches_set(host, easyprivacy):
        return "known_tracker"

    if host_matches_set(host, CDN_DOMAINS):
        return "cdn"

    return "unknown_third_party"


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify captured traffic CSV.")
    parser.add_argument("--input", required=True, help="Path to captured CSV file")
    parser.add_argument(
        "--provider",
        required=True,
        choices=["gmail", "outlook", "protonmail", "tutanota"],
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(base_dir, "..", "config")

    config = load_providers(os.path.join(config_dir, "providers.yaml"))
    first_party = config["providers"][args.provider]["first_party_domains"]

    # Infer phase from input path
    phase = "unknown"
    phases = config.get("phases", [])
    for p in phases:
        if p in args.input:
            phase = p
            break

    disconnect_map = load_disconnect(
        os.path.join(config_dir, "tracker_lists", "disconnect.json")
    )
    easyprivacy = load_easyprivacy(
        os.path.join(config_dir, "tracker_lists", "easyprivacy.txt")
    )

    df = pd.read_csv(args.input, dtype=str).fillna("")

    # Keep only the last occurrence of each (timestamp, host, path) to
    # prefer response-updated rows over request-only rows.
    df = df.drop_duplicates(subset=["timestamp", "host", "path"], keep="last")

    df["category"] = df["host"].apply(
        lambda h: classify_host(h, first_party, disconnect_map, easyprivacy)
    )

    out_dir = os.path.dirname(os.path.abspath(args.input))
    classified_path = os.path.join(out_dir, "classified_capture.csv")
    df.to_csv(classified_path, index=False)

    # Build summary
    third_party_mask = df["category"] != "first_party"
    third_party_domains = sorted(df.loc[third_party_mask, "host"].unique().tolist())

    by_category: dict[str, int] = df["category"].value_counts().to_dict()

    advertising_domains = sorted(
        df.loc[df["category"] == "advertising", "host"].unique().tolist()
    )
    analytics_domains = sorted(
        df.loc[df["category"] == "analytics", "host"].unique().tolist()
    )
    unknown_third_party_domains = sorted(
        df.loc[df["category"] == "unknown_third_party", "host"].unique().tolist()
    )

    summary = {
        "provider": args.provider,
        "phase": phase,
        "total_requests": len(df),
        "unique_domains": int(df["host"].nunique()),
        "third_party_domains": third_party_domains,
        "by_category": by_category,
        "advertising_domains": advertising_domains,
        "analytics_domains": analytics_domains,
        "unknown_third_party_domains": unknown_third_party_domains,
    }

    analysis_path = os.path.join(out_dir, "analysis.json")
    with open(analysis_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Rich terminal summary
    console = Console()
    table = Table(title=f"Traffic Summary — {args.provider} / {phase}")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        table.add_row(cat, str(count))
    console.print(table)
    console.print(f"\nTotal requests : {summary['total_requests']}")
    console.print(f"Unique domains : {summary['unique_domains']}")
    console.print(f"Third-party    : {len(third_party_domains)}")
    console.print(f"\nResults written to {out_dir}/")


if __name__ == "__main__":
    main()
