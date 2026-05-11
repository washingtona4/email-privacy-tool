#!/usr/bin/env python3
"""Generate a cross-provider HTML comparison report."""

import json
import os

from jinja2 import Template

PROVIDERS = ["gmail", "outlook", "protonmail", "tutanota"]
PHASES = ["account_creation", "idle", "active_usage", "tracker_test"]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Email Privacy Analysis Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; color: #222; background: #fafafa; }
    h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: .4rem; }
    h2 { color: #16213e; margin-top: 2rem; }
    h3 { color: #0f3460; }
    .team { font-size: .95rem; color: #555; margin-bottom: 1.5rem; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0; background: #fff; }
    th { background: #1a1a2e; color: #fff; padding: .5rem .8rem; text-align: left; }
    td { border: 1px solid #ddd; padding: .45rem .8rem; }
    tr:nth-child(even) td { background: #f2f2f2; }
    .verdict-good { color: #2ecc71; font-weight: bold; }
    .verdict-bad  { color: #e74c3c; font-weight: bold; }
    .domain-list { font-size: .85rem; color: #444; }
    .tag { display: inline-block; border-radius: 3px; padding: 1px 6px; font-size: .8rem;
           margin: 1px; color: #fff; }
    .tag-advertising   { background: #e74c3c; }
    .tag-analytics     { background: #e67e22; }
    .tag-social        { background: #3498db; }
    .tag-fingerprinting{ background: #9b59b6; }
    .tag-known_tracker { background: #c0392b; }
    .tag-cdn           { background: #27ae60; }
    .tag-unknown_third_party { background: #7f8c8d; }
    .missing { color: #aaa; font-style: italic; }
  </style>
</head>
<body>

<h1>Email Privacy Analysis — Network Traffic Study</h1>
<div class="team">
  Northwestern University CS Research Project &nbsp;|&nbsp;
  Team: Andre (Gmail) &bull; Daniel (Outlook) &bull; Rishi (ProtonMail) &bull; Ryan (Tutanota)
</div>

<h2>Summary: Total Requests by Provider &amp; Phase</h2>
<table>
  <tr>
    <th>Phase</th>
    {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
  </tr>
  {% for phase in phases %}
  <tr>
    <td><strong>{{ phase.replace('_', ' ') | title }}</strong></td>
    {% for p in providers %}
    <td>
      {% if data[p][phase] %}
        {{ data[p][phase].total_requests }}
      {% else %}
        <span class="missing">—</span>
      {% endif %}
    </td>
    {% endfor %}
  </tr>
  {% endfor %}
</table>

<h2>Summary: Unique Domains by Provider &amp; Phase</h2>
<table>
  <tr>
    <th>Phase</th>
    {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
  </tr>
  {% for phase in phases %}
  <tr>
    <td><strong>{{ phase.replace('_', ' ') | title }}</strong></td>
    {% for p in providers %}
    <td>
      {% if data[p][phase] %}
        {{ data[p][phase].unique_domains }}
      {% else %}
        <span class="missing">—</span>
      {% endif %}
    </td>
    {% endfor %}
  </tr>
  {% endfor %}
</table>

<h2>Summary: Third-Party Domain Count by Provider &amp; Phase</h2>
<table>
  <tr>
    <th>Phase</th>
    {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
  </tr>
  {% for phase in phases %}
  <tr>
    <td><strong>{{ phase.replace('_', ' ') | title }}</strong></td>
    {% for p in providers %}
    <td>
      {% if data[p][phase] %}
        {{ data[p][phase].third_party_domains | length }}
      {% else %}
        <span class="missing">—</span>
      {% endif %}
    </td>
    {% endfor %}
  </tr>
  {% endfor %}
</table>

{% for p in providers %}
<h2>{{ p | title }}: Third-Party Domains by Category</h2>
{% set found_any = [] %}
{% for phase in phases %}
  {% if data[p][phase] and data[p][phase].third_party_domains %}
    {% set _ = found_any.append(1) %}
  {% endif %}
{% endfor %}
{% if found_any %}
  {% for phase in phases %}
    {% if data[p][phase] and data[p][phase].third_party_domains %}
    <h3>{{ phase.replace('_', ' ') | title }}</h3>
    <div class="domain-list">
      {% for domain in data[p][phase].third_party_domains %}
        {% set cat = data[p][phase].by_category_per_domain.get(domain, 'unknown_third_party') %}
        <span class="tag tag-{{ cat }}">{{ domain }}</span>
      {% endfor %}
    </div>
    {% endif %}
  {% endfor %}
{% else %}
  <p class="missing">No data collected yet.</p>
{% endif %}
{% endfor %}

<h2>Encryption Verdicts</h2>
<table>
  <tr>
    <th>Provider</th>
    <th>Phase</th>
    <th>Verdict</th>
  </tr>
  {% for p in providers %}
    {% for phase in phases %}
      {% if verdicts[p][phase] %}
      <tr>
        <td>{{ p | title }}</td>
        <td>{{ phase.replace('_', ' ') | title }}</td>
        <td class="{{ 'verdict-good' if 'end-to-end encrypted' in verdicts[p][phase] else 'verdict-bad' }}">
          {{ verdicts[p][phase] }}
        </td>
      </tr>
      {% endif %}
    {% endfor %}
  {% endfor %}
</table>

</body>
</html>
"""


def load_analysis(provider: str, phase: str) -> dict | None:
    path = os.path.join("output", provider, phase, "analysis.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_encryption(provider: str, phase: str) -> str | None:
    path = os.path.join("output", provider, phase, "encryption_analysis.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("verdict")


def build_category_per_domain(analysis: dict) -> dict[str, str]:
    """Invert by_category into domain -> category for template use."""
    mapping: dict[str, str] = {}
    category_lists = {
        "advertising": analysis.get("advertising_domains", []),
        "analytics": analysis.get("analytics_domains", []),
        "unknown_third_party": analysis.get("unknown_third_party_domains", []),
    }
    for cat, domains in category_lists.items():
        for d in domains:
            mapping[d] = cat
    # remaining third-party domains not in specific lists
    for d in analysis.get("third_party_domains", []):
        if d not in mapping:
            mapping[d] = "unknown_third_party"
    return mapping


def main() -> None:
    data: dict[str, dict] = {}
    verdicts: dict[str, dict] = {}

    for provider in PROVIDERS:
        data[provider] = {}
        verdicts[provider] = {}
        for phase in PHASES:
            analysis = load_analysis(provider, phase)
            if analysis is not None:
                analysis["by_category_per_domain"] = build_category_per_domain(analysis)
            data[provider][phase] = analysis
            verdicts[provider][phase] = load_encryption(provider, phase)

    template = Template(HTML_TEMPLATE)
    html = template.render(
        providers=PROVIDERS,
        phases=PHASES,
        data=data,
        verdicts=verdicts,
    )

    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", "final_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
