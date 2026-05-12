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
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      color: #1a1a1a;
      background: #f5f5f5;
      padding: 2rem;
    }
    .page {
      max-width: 1100px;
      margin: 0 auto;
      background: #fff;
      border: 1px solid #e0e0e0;
      padding: 2rem 2.5rem 3rem;
    }
    h1 {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.3px;
      color: #111;
      border-bottom: 2px solid #111;
      padding-bottom: 8px;
      margin-bottom: 4px;
    }
    .subtitle {
      font-size: 11px;
      color: #666;
      margin-bottom: 2rem;
      letter-spacing: 0.3px;
      text-transform: uppercase;
    }
    h2 {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #444;
      margin: 2.5rem 0 0.75rem;
      padding-bottom: 4px;
      border-bottom: 1px solid #e8e8e8;
    }
    h3 {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #888;
      margin: 1.5rem 0 0.5rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 0.5rem;
    }
    thead tr {
      background: #f0f0f0;
      border-bottom: 1.5px solid #ccc;
    }
    th {
      text-align: left;
      padding: 7px 12px;
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: #444;
    }
    th:not(:first-child) { text-align: center; }
    td {
      padding: 6px 12px;
      border-bottom: 1px solid #f0f0f0;
      color: #222;
    }
    td:not(:first-child) { text-align: center; }
    tr:last-child td { border-bottom: none; }
    tbody tr:hover { background: #fafafa; }
    .phase-label { font-weight: 500; color: #333; }
    .missing { color: #bbb; }
    .num-high { color: #c0392b; font-weight: 600; }
    .num-low  { color: #27ae60; font-weight: 600; }
    .num-mid  { color: #e67e22; font-weight: 500; }
    .leak-yes { color: #c0392b; font-weight: 600; }
    .leak-no  { color: #27ae60; }
    .verdict-good { color: #27ae60; font-weight: 600; }
    .verdict-bad  { color: #c0392b; font-weight: 600; }
    .tag {
      display: inline-block;
      font-size: 10px;
      padding: 2px 7px;
      border-radius: 2px;
      margin: 2px 2px 2px 0;
      font-weight: 500;
      letter-spacing: 0.2px;
    }
    .tag-advertising    { background: #fdecea; color: #c0392b; border: 1px solid #f5c6c3; }
    .tag-analytics      { background: #fef3e2; color: #d35400; border: 1px solid #f9d9a8; }
    .tag-social         { background: #e8f4fd; color: #2980b9; border: 1px solid #aed6f1; }
    .tag-fingerprinting { background: #f5eef8; color: #7d3c98; border: 1px solid #d7bde2; }
    .tag-known_tracker  { background: #fdecea; color: #922b21; border: 1px solid #f1948a; }
    .tag-cdn            { background: #eafaf1; color: #1e8449; border: 1px solid #a9dfbf; }
    .tag-unknown_third_party { background: #f2f3f4; color: #626567; border: 1px solid #d5d8dc; }
    .provider-section {
      margin-top: 2rem;
      border: 1px solid #e8e8e8;
      padding: 1rem 1.25rem;
    }
    .provider-header {
      font-size: 13px;
      font-weight: 600;
      color: #111;
      text-transform: capitalize;
      margin-bottom: 0.75rem;
      padding-bottom: 6px;
      border-bottom: 1px solid #eee;
    }
    .domain-list { line-height: 2; }
    .no-data { color: #bbb; font-style: italic; font-size: 11px; }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 1rem 0 1.5rem;
      font-size: 10px;
    }
    .legend-item { display: flex; align-items: center; gap: 4px; }
    .legend-dot {
      width: 8px; height: 8px; border-radius: 1px;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin: 1.5rem 0;
    }
    .summary-card {
      border: 1px solid #e8e8e8;
      padding: 0.75rem 1rem;
    }
    .summary-card .label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #888;
      margin-bottom: 4px;
    }
    .summary-card .value {
      font-size: 22px;
      font-weight: 600;
      color: #111;
      line-height: 1;
    }
    .summary-card .sub {
      font-size: 10px;
      color: #aaa;
      margin-top: 3px;
    }
    .footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid #e8e8e8;
      font-size: 10px;
      color: #aaa;
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }
  </style>
</head>
<body>
<div class="page">

  <h1>Email Privacy Analysis — Network Traffic Study</h1>
  <p class="subtitle">Northwestern University &nbsp;·&nbsp; Andre Washington &nbsp;·&nbsp; Daniel Rivero &nbsp;·&nbsp; Rishi Ramaiya &nbsp;·&nbsp; Ryan Rosu</p>

  <h2>Legend</h2>
  <div class="legend">
    <span class="legend-item"><span class="legend-dot" style="background:#c0392b;"></span> Advertising</span>
    <span class="legend-item"><span class="legend-dot" style="background:#d35400;"></span> Analytics</span>
    <span class="legend-item"><span class="legend-dot" style="background:#2980b9;"></span> Social</span>
    <span class="legend-item"><span class="legend-dot" style="background:#7d3c98;"></span> Fingerprinting</span>
    <span class="legend-item"><span class="legend-dot" style="background:#922b21;"></span> Known tracker</span>
    <span class="legend-item"><span class="legend-dot" style="background:#1e8449;"></span> CDN</span>
    <span class="legend-item"><span class="legend-dot" style="background:#626567;"></span> Unknown third party</span>
  </div>

  <h2>Total requests by provider and phase</h2>
  <table>
    <thead>
      <tr>
        <th>Phase</th>
        {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for phase in phases %}
      <tr>
        <td class="phase-label">{{ phase.replace('_', ' ') | title }}</td>
        {% for p in providers %}
        <td>
          {% if data[p][phase] %}{{ data[p][phase].total_requests }}
          {% else %}<span class="missing">—</span>{% endif %}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Unique domains contacted</h2>
  <table>
    <thead>
      <tr>
        <th>Phase</th>
        {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for phase in phases %}
      <tr>
        <td class="phase-label">{{ phase.replace('_', ' ') | title }}</td>
        {% for p in providers %}
        <td>
          {% if data[p][phase] %}{{ data[p][phase].unique_domains }}
          {% else %}<span class="missing">—</span>{% endif %}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Third-party domain count</h2>
  <table>
    <thead>
      <tr>
        <th>Phase</th>
        {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for phase in phases %}
      <tr>
        <td class="phase-label">{{ phase.replace('_', ' ') | title }}</td>
        {% for p in providers %}
        <td>
          {% if data[p][phase] %}{{ data[p][phase].third_party_domains | length }}
          {% else %}<span class="missing">—</span>{% endif %}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Email address leaks detected</h2>
  <table>
    <thead>
      <tr>
        <th>Phase</th>
        {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for phase in phases %}
      <tr>
        <td class="phase-label">{{ phase.replace('_', ' ') | title }}</td>
        {% for p in providers %}
        <td>
          {% if data[p][phase] %}
            {% if data[p][phase].email_leak_count > 0 %}
              <span class="leak-yes">{{ data[p][phase].email_leak_count }}</span>
            {% else %}
              <span class="leak-no">0</span>
            {% endif %}
          {% else %}<span class="missing">—</span>{% endif %}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Category breakdown by provider</h2>
  {% for p in providers %}
  <div class="provider-section">
    <div class="provider-header">{{ p | title }}</div>
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
      <p class="no-data">No data collected yet.</p>
    {% endif %}
  </div>
  {% endfor %}

  <h2>Encryption assessment</h2>
  <table>
    <thead>
      <tr>
        <th>Provider</th>
        <th>Phase</th>
        <th>Verdict</th>
      </tr>
    </thead>
    <tbody>
      {% set any_verdict = [] %}
      {% for p in providers %}
        {% for phase in phases %}
          {% if verdicts[p][phase] %}
            {% set _ = any_verdict.append(1) %}
            <tr>
              <td style="text-transform: capitalize;">{{ p }}</td>
              <td>{{ phase.replace('_', ' ') | title }}</td>
              <td class="{{ 'verdict-good' if 'end-to-end encrypted' in verdicts[p][phase] else 'verdict-bad' }}">
                {{ verdicts[p][phase] }}
              </td>
            </tr>
          {% endif %}
        {% endfor %}
      {% endfor %}
      {% if not any_verdict %}
        <tr><td colspan="3" class="no-data">No encryption analysis data yet. Run encryption_checker.py on active_usage captures.</td></tr>
      {% endif %}
    </tbody>
  </table>

  <div class="footer">Generated by email-privacy-tool &nbsp;·&nbsp; Northwestern University CS</div>
</div>
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
