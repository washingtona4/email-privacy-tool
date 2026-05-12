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
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      font-size: 12px;
      color: #111;
      background: #fff;
      padding: 2.5rem 3rem;
    }
    .report-title {
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: #000;
      margin-bottom: 2px;
    }
    .report-meta {
      font-size: 10px;
      color: #777;
      letter-spacing: 0.4px;
      margin-bottom: 2.5rem;
      border-bottom: 2px solid #000;
      padding-bottom: 8px;
    }
    .section-title {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #000;
      margin: 2.5rem 0 0.6rem;
      padding-bottom: 3px;
      border-bottom: 1px solid #000;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      margin-bottom: 0.25rem;
    }
    thead tr { border-bottom: 1.5px solid #000; }
    th {
      text-align: left;
      padding: 5px 10px;
      font-weight: 700;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #000;
      background: #f7f7f7;
    }
    th:not(:first-child) { text-align: right; }
    td {
      padding: 5px 10px;
      border-bottom: 1px solid #e8e8e8;
      color: #111;
    }
    td:not(:first-child) { text-align: right; }
    tr:last-child td { border-bottom: 2px solid #000; }
    .phase-label { font-weight: 600; color: #000; }
    .missing { color: #bbb; }
    .high { color: #b91c1c; font-weight: 700; }
    .low  { color: #15803d; font-weight: 700; }
    .leak-yes { color: #b91c1c; font-weight: 700; }
    .leak-no  { color: #15803d; }
    .verdict-good { color: #15803d; font-weight: 700; }
    .verdict-bad  { color: #b91c1c; font-weight: 700; }
    .domain-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      margin-bottom: 1.5rem;
    }
    .domain-table th {
      background: #f7f7f7;
      border-bottom: 1.5px solid #000;
      padding: 4px 10px;
      text-align: left;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .domain-table td {
      padding: 4px 10px;
      border-bottom: 1px solid #ebebeb;
      vertical-align: top;
    }
    .domain-table tr:last-child td { border-bottom: 2px solid #000; }
    .domain-table .provider-col { font-weight: 700; text-transform: capitalize; width: 100px; }
    .domain-table .phase-col { color: #555; width: 120px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.3px; }
    .cat-dot {
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      margin-right: 4px;
      vertical-align: middle;
    }
    .cat-advertising    { background: #b91c1c; }
    .cat-analytics      { background: #c2410c; }
    .cat-social         { background: #1d4ed8; }
    .cat-fingerprinting { background: #6d28d9; }
    .cat-known_tracker  { background: #7f1d1d; }
    .cat-cdn            { background: #166534; }
    .cat-unknown_third_party { background: #6b7280; }
    .domain-entry {
      display: inline-block;
      font-size: 10px;
      margin: 1px 6px 1px 0;
      color: #111;
    }
    .legend-row {
      display: flex;
      gap: 20px;
      margin: 0.75rem 0 2rem;
      font-size: 10px;
      color: #333;
      flex-wrap: wrap;
    }
    .legend-item { display: flex; align-items: center; gap: 5px; }
    .no-data { color: #aaa; font-style: italic; font-size: 10px; }
    .footer {
      margin-top: 3rem;
      padding-top: 8px;
      border-top: 1px solid #ccc;
      font-size: 9px;
      color: #aaa;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
  </style>
</head>
<body>

  <div class="report-title">Email Privacy Analysis — Network Traffic Study</div>
  <div class="report-meta">Northwestern University &nbsp;·&nbsp; Andre Washington &nbsp;·&nbsp; Daniel Rivero &nbsp;·&nbsp; Rishi Ramaiya &nbsp;·&nbsp; Ryan Rosu</div>

  <div class="section-title">Total requests by provider and phase</div>
  <table>
    <thead><tr>
      <th>Phase</th>
      {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
    </tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>{% if data[p][phase] %}{{ data[p][phase].total_requests }}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title">Unique domains contacted</div>
  <table>
    <thead><tr>
      <th>Phase</th>
      {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
    </tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>{% if data[p][phase] %}{{ data[p][phase].unique_domains }}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title">Third-party domains contacted</div>
  <table>
    <thead><tr>
      <th>Phase</th>
      {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
    </tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>{% if data[p][phase] %}{{ data[p][phase].third_party_domains | length }}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title">Email address leaks detected</div>
  <table>
    <thead><tr>
      <th>Phase</th>
      {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
    </tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% if data[p][phase].email_leak_count > 0 %}<span class="leak-yes">{{ data[p][phase].email_leak_count }}</span>
          {% else %}<span class="leak-no">0</span>{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title">Third-party domain breakdown</div>
  <div class="legend-row">
    <span class="legend-item"><span class="cat-dot cat-advertising"></span>Advertising</span>
    <span class="legend-item"><span class="cat-dot cat-analytics"></span>Analytics</span>
    <span class="legend-item"><span class="cat-dot cat-social"></span>Social</span>
    <span class="legend-item"><span class="cat-dot cat-fingerprinting"></span>Fingerprinting</span>
    <span class="legend-item"><span class="cat-dot cat-known_tracker"></span>Known tracker</span>
    <span class="legend-item"><span class="cat-dot cat-cdn"></span>CDN</span>
    <span class="legend-item"><span class="cat-dot cat-unknown_third_party"></span>Unknown third party</span>
  </div>
  <table class="domain-table">
    <thead><tr>
      <th>Provider</th>
      <th>Phase</th>
      <th>Third-party domains</th>
    </tr></thead>
    <tbody>
    {% for p in providers %}
      {% for phase in phases %}
        {% if data[p][phase] and data[p][phase].third_party_domains %}
        <tr>
          <td class="provider-col">{{ p | title }}</td>
          <td class="phase-col">{{ phase.replace('_',' ') }}</td>
          <td>
            {% for domain in data[p][phase].third_party_domains %}
              {% set cat = data[p][phase].by_category_per_domain.get(domain, 'unknown_third_party') %}
              <span class="domain-entry"><span class="cat-dot cat-{{ cat }}"></span>{{ domain }}</span>
            {% endfor %}
          </td>
        </tr>
        {% elif data[p][phase] %}
        <tr>
          <td class="provider-col">{{ p | title }}</td>
          <td class="phase-col">{{ phase.replace('_',' ') }}</td>
          <td class="no-data">none detected</td>
        </tr>
        {% endif %}
      {% endfor %}
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title">Encryption assessment</div>
  <table>
    <thead><tr>
      <th>Provider</th>
      <th>Phase</th>
      <th>Verdict</th>
    </tr></thead>
    <tbody>
    {% set any_verdict = [] %}
    {% for p in providers %}
      {% for phase in phases %}
        {% if verdicts[p][phase] %}
          {% set _ = any_verdict.append(1) %}
          <tr>
            <td style="font-weight:600;text-transform:capitalize;">{{ p }}</td>
            <td>{{ phase.replace('_',' ') | title }}</td>
            <td class="{{ 'verdict-good' if 'end-to-end encrypted' in verdicts[p][phase] else 'verdict-bad' }}">{{ verdicts[p][phase] }}</td>
          </tr>
        {% endif %}
      {% endfor %}
    {% endfor %}
    {% if not any_verdict %}
      <tr><td colspan="3" class="no-data">No encryption data yet — run encryption_checker.py on active_usage captures.</td></tr>
    {% endif %}
    </tbody>
  </table>

  <div class="footer">Generated by email-privacy-tool &nbsp;·&nbsp; Northwestern University CS</div>

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
    mapping: dict[str, str] = {}
    category_lists = {
        "advertising": analysis.get("advertising_domains", []),
        "analytics": analysis.get("analytics_domains", []),
        "unknown_third_party": analysis.get("unknown_third_party_domains", []),
    }
    for cat, domains in category_lists.items():
        for d in domains:
            mapping[d] = cat
    for d in analysis.get("third_party_domains", []):
        if d not in mapping:
            for cat in ["social", "fingerprinting", "known_tracker", "cdn"]:
                cat_domains = analysis.get(f"{cat}_domains", [])
                if d in cat_domains:
                    mapping[d] = cat
                    break
            else:
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
    html = template.render(providers=PROVIDERS, phases=PHASES, data=data, verdicts=verdicts)

    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", "final_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
