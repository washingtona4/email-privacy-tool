#!/usr/bin/env python3
"""Generate a cross-provider HTML comparison report."""

import json
import os
from datetime import datetime

from jinja2 import Template

PROVIDERS = ["gmail", "outlook", "protonmail", "tutanota"]
PHASES = ["account_creation", "idle", "active_usage", "tracker_test"]

PHASE_DESCRIPTIONS = {
    "account_creation": "Capture from first page load through completed account setup",
    "idle": "15 minutes with inbox open and no user interaction",
    "active_usage": "Composing, sending, and replying to email",
    "tracker_test": "Opening an email containing a web bug / canary token tracking pixel",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Email Privacy Analysis Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 12px; color: #111; background: #fff; padding: 2.5rem 3rem; max-width: 1400px; margin: 0 auto; }
    .report-title { font-size: 18px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #000; margin-bottom: 4px; }
    .report-subtitle { font-size: 12px; color: #444; margin-bottom: 4px; }
    .report-meta { font-size: 10px; color: #777; letter-spacing: 0.4px; margin-bottom: 2.5rem; border-bottom: 2px solid #000; padding-bottom: 8px; }
    .section-title { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #000; margin: 2.5rem 0 0.6rem; padding-bottom: 3px; border-bottom: 1px solid #000; }
    .subsection-title { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #333; margin: 1.5rem 0 0.4rem; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 0.25rem; }
    thead tr { border-bottom: 1.5px solid #000; }
    th { text-align: left; padding: 5px 10px; font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #000; background: #f7f7f7; }
    th:not(:first-child) { text-align: right; }
    td { padding: 5px 10px; border-bottom: 1px solid #e8e8e8; color: #111; }
    td:not(:first-child) { text-align: right; }
    tr:last-child td { border-bottom: 2px solid #000; }
    tr:hover td { background: #fafafa; }
    .phase-label { font-weight: 600; color: #000; }
    .missing { color: #bbb; }
    .high { color: #b91c1c; font-weight: 700; }
    .low { color: #15803d; font-weight: 700; }
    .mid { color: #b45309; font-weight: 700; }
    .leak-yes { color: #b91c1c; font-weight: 700; }
    .leak-no { color: #15803d; }
    .verdict-good { color: #15803d; font-weight: 700; }
    .verdict-bad { color: #b91c1c; font-weight: 700; }
    .domain-table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 1.5rem; }
    .domain-table th { background: #f7f7f7; border-bottom: 1.5px solid #000; padding: 4px 10px; text-align: left; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
    .domain-table td { padding: 4px 10px; border-bottom: 1px solid #ebebeb; vertical-align: top; }
    .domain-table tr:last-child td { border-bottom: 2px solid #000; }
    .domain-table .provider-col { font-weight: 700; text-transform: capitalize; width: 100px; }
    .domain-table .phase-col { color: #555; width: 120px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.3px; }
    .cat-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
    .cat-advertising { background: #b91c1c; }
    .cat-analytics { background: #c2410c; }
    .cat-social { background: #1d4ed8; }
    .cat-fingerprinting { background: #6d28d9; }
    .cat-known_tracker { background: #7f1d1d; }
    .cat-cdn { background: #166534; }
    .cat-unknown_third_party { background: #6b7280; }
    .cat-first_party { background: #000; }
    .domain-entry { display: inline-block; font-size: 10px; margin: 1px 6px 1px 0; color: #111; }
    .legend-row { display: flex; gap: 20px; margin: 0.75rem 0 1rem; font-size: 10px; color: #333; flex-wrap: wrap; }
    .legend-item { display: flex; align-items: center; gap: 5px; }
    .no-data { color: #aaa; font-style: italic; font-size: 10px; }
    .footer { margin-top: 3rem; padding-top: 8px; border-top: 1px solid #ccc; font-size: 9px; color: #aaa; text-transform: uppercase; letter-spacing: 0.5px; }
    .finding-box { border-left: 3px solid #000; padding: 8px 12px; margin: 6px 0; background: #fafafa; font-size: 11px; line-height: 1.5; }
    .finding-box.positive { border-left-color: #15803d; }
    .finding-box.negative { border-left-color: #b91c1c; }
    .finding-box.neutral { border-left-color: #6b7280; }
    .finding-box .finding-label { font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 1rem; }
    .provider-card { border: 1px solid #e8e8e8; padding: 12px; }
    .provider-card h3 { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #e8e8e8; padding-bottom: 6px; margin-bottom: 8px; }
    .stat-row { display: flex; justify-content: space-between; font-size: 10px; padding: 2px 0; border-bottom: 1px solid #f0f0f0; }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: #555; }
    .stat-value { font-weight: 600; }
    .phase-desc { font-size: 10px; color: #666; font-style: italic; margin-bottom: 0.5rem; }
    .bar-container { display: flex; align-items: center; gap: 8px; }
    .bar { height: 8px; background: #000; display: inline-block; min-width: 2px; }
    .bar-gmail { background: #4285f4; }
    .bar-outlook { background: #0078d4; }
    .bar-protonmail { background: #6d4aff; }
    .bar-tutanota { background: #c20000; }
    .bar-label { font-size: 10px; color: #555; min-width: 30px; }
    .toc { margin: 1rem 0 2rem; font-size: 11px; }
    .toc a { color: #000; text-decoration: none; display: block; padding: 2px 0; border-bottom: 1px dotted #ddd; }
    .toc a:hover { text-decoration: underline; }
    .toc-section { font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 8px; margin-bottom: 2px; color: #555; }
    .badge { display: inline-block; font-size: 9px; font-weight: 700; padding: 1px 5px; border-radius: 2px; text-transform: uppercase; letter-spacing: 0.3px; }
    .badge-red { background: #fee2e2; color: #b91c1c; }
    .badge-green { background: #dcfce7; color: #15803d; }
    .badge-gray { background: #f3f4f6; color: #6b7280; }
    .badge-yellow { background: #fef9c3; color: #854d0e; }
    summary { cursor: pointer; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 4px 0; }
    details { margin: 4px 0; }
    .note { font-size: 10px; color: #666; font-style: italic; margin: 4px 0 8px; }
  </style>
</head>
<body>

  <div class="report-title">Email Privacy Analysis — Network Traffic Study</div>
  <div class="report-subtitle">A comparative measurement of network-level data collection across four email providers</div>
  <div class="report-meta">
    Northwestern University &nbsp;·&nbsp; Andre Washington &nbsp;·&nbsp; Daniel Rivero &nbsp;·&nbsp; Rishi Ramaiya &nbsp;·&nbsp; Ryan Rosu
    &nbsp;·&nbsp; Generated {{ generated_at }}
  </div>

  <!-- TABLE OF CONTENTS -->
  <div class="section-title">Contents</div>
  <div class="toc">
    <div class="toc-section">Overview</div>
    <a href="#methodology">Methodology &amp; Experimental Design</a>
    <a href="#key-findings">Key Findings Summary</a>
    <div class="toc-section">Quantitative Results</div>
    <a href="#total-requests">Total Requests by Provider and Phase</a>
    <a href="#unique-domains">Unique Domains Contacted</a>
    <a href="#third-party">Third-Party Domains Contacted</a>
    <a href="#browser-noise">Browser Noise Filtered</a>
    <a href="#category-breakdown">Request Category Breakdown</a>
    <a href="#email-leaks">Email Address Leak Detection</a>
    <a href="#data-volume">Data Volume</a>
    <div class="toc-section">Qualitative Analysis</div>
    <a href="#domain-breakdown">Third-Party Domain Breakdown by Provider</a>
    <a href="#provider-profiles">Provider Profiles</a>
    <a href="#tracker-test">Tracker Test Results</a>
    <a href="#encryption">Encryption Assessment</a>
    <a href="#limitations">Methodology Limitations</a>
  </div>

  <!-- METHODOLOGY -->
  <div class="section-title" id="methodology">Methodology &amp; Experimental Design</div>
  <p style="font-size:11px;line-height:1.6;margin-bottom:0.75rem;">
    All traffic was captured using mitmproxy acting as a TLS-intercepting proxy on a clean Ubuntu 26.04 virtual machine. Firefox was configured to route all traffic through the proxy, and the mitmproxy CA certificate was installed in the browser. A fresh VM snapshot was restored before each experiment to ensure identical baseline conditions. Browser background noise from Firefox itself (telemetry, safe browsing, updates) was identified and filtered before analysis. Domains were classified using the EasyPrivacy and Disconnect.me tracker databases.
  </p>
  <table>
    <thead><tr><th>Phase</th><th style="text-align:left;">Description</th></tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      <td style="text-align:left;">{{ phase_descriptions[phase] }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- KEY FINDINGS -->
  <div class="section-title" id="key-findings">Key Findings Summary</div>

  <div class="finding-box negative">
    <div class="finding-label">Gmail idle activity</div>
    Gmail generated 1,157 requests and contacted 10 third-party domains during 15 minutes of zero user interaction — more traffic than during account creation. Google Analytics, Tag Manager, and four DoubleClick subdomains were active with no user activity.
  </div>

  <div class="finding-box negative">
    <div class="finding-label">Password in plaintext request body</div>
    During Gmail account creation, the test account password appeared in plaintext in a POST request body. While protected by TLS in transit, this confirms Google's servers receive and process the password in readable form before hashing.
  </div>

  <div class="finding-box negative">
    <div class="finding-label">Privacy providers contact Google infrastructure</div>
    Both ProtonMail and Tutanota contacted Google advertising infrastructure (googleadservices.com, googletagmanager.com) during account creation, despite marketing themselves as Google alternatives.
  </div>

  <div class="finding-box positive">
    <div class="finding-label">Tutanota idle is remarkably clean</div>
    Tutanota generated only 40 requests and contacted 1 domain during idle — 29x fewer requests than Gmail. The single domain contacted was its own first-party API.
  </div>

  <div class="finding-box neutral">
    <div class="finding-label">Gmail proxies tracking pixels</div>
    When a canary token web bug was opened in Gmail, the request to the tracking server came from IP 74.125.215.66 (Google's image proxy) rather than the user's IP. Gmail protects users from third-party IP tracking but gains visibility into all external URLs in user emails.
  </div>

  <div class="finding-box neutral">
    <div class="finding-label">ProtonMail account creation has most third-party domains</div>
    ProtonMail contacted 19 third-party domains during account creation — more than Gmail (5). This is largely explained by payment processors (Stripe, Chargebee) and hCaptcha, but raises questions about the gap between privacy claims and signup behavior.
  </div>

  <div class="finding-box positive">
    <div class="finding-label">Tutanota email leak false positives confirmed</div>
    The classifier flagged 3 email address detections for Tutanota account creation. Manual inspection confirmed all three were legitimate API calls to app.tuta.com (Tutanota's own server) required to create the account — not leaks to third parties.
  </div>

  <!-- TOTAL REQUESTS -->
  <div class="section-title" id="total-requests">Total Requests by Provider and Phase</div>
  <p class="note">All requests captured by mitmproxy including first-party, third-party, and filtered browser noise.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% set val = data[p][phase].total_requests %}
          {% if val > 800 %}<span class="high">{{ val }}</span>
          {% elif val > 300 %}<span class="mid">{{ val }}</span>
          {% else %}<span class="low">{{ val }}</span>{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- UNIQUE DOMAINS -->
  <div class="section-title" id="unique-domains">Unique Domains Contacted</div>
  <p class="note">Count of distinct hostnames contacted across all requests in each phase, including first-party domains.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}<td>{% if data[p][phase] %}{{ data[p][phase].unique_domains }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- THIRD PARTY DOMAINS -->
  <div class="section-title" id="third-party">Third-Party Domains Contacted</div>
  <p class="note">Domains not belonging to the provider's own infrastructure, after browser noise filtering.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% set val = data[p][phase].third_party_domains | length %}
          {% if val > 10 %}<span class="high">{{ val }}</span>
          {% elif val > 5 %}<span class="mid">{{ val }}</span>
          {% elif val > 0 %}<span class="low">{{ val }}</span>
          {% else %}0{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- BROWSER NOISE -->
  <div class="section-title" id="browser-noise">Browser Noise Requests Filtered</div>
  <p class="note">Requests from Firefox itself (telemetry, safe browsing, push notifications) removed before analysis to isolate provider behavior.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}<td>{% if data[p][phase] %}{{ data[p][phase].get('browser_noise_requests_filtered', 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- CATEGORY BREAKDOWN -->
  <div class="section-title" id="category-breakdown">Request Category Breakdown</div>
  <p class="note">Classification of all captured requests by category using EasyPrivacy and Disconnect.me databases.</p>
  <div class="legend-row">
    <span class="legend-item"><span class="cat-dot cat-first_party"></span>First party</span>
    <span class="legend-item"><span class="cat-dot cat-advertising"></span>Advertising</span>
    <span class="legend-item"><span class="cat-dot cat-analytics"></span>Analytics</span>
    <span class="legend-item"><span class="cat-dot cat-known_tracker"></span>Known tracker</span>
    <span class="legend-item"><span class="cat-dot cat-unknown_third_party"></span>Unknown third party</span>
  </div>
  {% for phase in phases %}
  <div class="subsection-title">{{ phase.replace('_',' ') | title }}</div>
  <p class="phase-desc">{{ phase_descriptions[phase] }}</p>
  <table>
    <thead><tr>
      <th>Category</th>
      {% for p in providers %}<th>{{ p | title }}</th>{% endfor %}
    </tr></thead>
    <tbody>
    {% set cats = ['first_party', 'advertising', 'analytics', 'known_tracker', 'unknown_third_party'] %}
    {% for cat in cats %}
    <tr>
      <td><span class="cat-dot cat-{{ cat }}"></span>{{ cat.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {{ data[p][phase].get('by_category', {}).get(cat, 0) }}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endfor %}

  <!-- EMAIL LEAKS -->
  <div class="section-title" id="email-leaks">Email Address Leak Detection</div>
  <p class="note">Regex scan of request body snippets for email address patterns. Detections require manual verification to distinguish legitimate first-party API calls from actual third-party leaks.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% set leak_count = data[p][phase].get('email_leak_count', 0) %}
          {% if leak_count > 0 %}<span class="leak-yes">{{ leak_count }}</span>{% else %}<span class="leak-no">0</span>{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% for p in providers %}
    {% for phase in phases %}
      {% if data[p][phase] and data[p][phase].get('email_leaks') %}
      <details>
        <summary>{{ p | title }} — {{ phase.replace('_',' ') | title }} — {{ data[p][phase].get('email_leak_count', 0) }} detection(s)</summary>
        <table style="margin-top:6px;">
          <thead><tr><th style="text-align:left;">Host</th><th style="text-align:left;">Path</th><th style="text-align:left;">Emails Found</th><th>Verdict</th></tr></thead>
          <tbody>
          {% for leak in data[p][phase].email_leaks %}
          <tr>
            <td style="text-align:left;font-family:monospace;font-size:10px;">{{ leak.host }}</td>
            <td style="text-align:left;font-family:monospace;font-size:10px;">{{ leak.path }}</td>
            <td style="text-align:left;font-family:monospace;font-size:10px;">{{ leak.emails_found | join(', ') }}</td>
            <td>
              {% if 'tuta.com' in leak.host or 'proton' in leak.host or 'gmail' in leak.host or 'outlook' in leak.host %}
                <span class="badge badge-green">First-party — expected</span>
              {% else %}
                <span class="badge badge-red">Verify manually</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
      </details>
      {% endif %}
    {% endfor %}
  {% endfor %}

  <!-- DATA VOLUME -->
  <div class="section-title" id="data-volume">Data Volume (Request + Response Sizes)</div>
  <p class="note">Total bytes sent and received per phase. Larger numbers indicate more data transferred to/from provider and third-party servers.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% set rb = data[p][phase].get('total_request_size', 0) %}
          {% set sb = data[p][phase].get('total_response_size', 0) %}
          {% if rb + sb > 0 %}
            {{ "%.1f"|format((rb + sb) / 1024) }} KB
          {% else %}—{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- DOMAIN BREAKDOWN -->
  <div class="section-title" id="domain-breakdown">Third-Party Domain Breakdown by Provider</div>
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
    <thead><tr><th>Provider</th><th>Phase</th><th>Third-party domains</th></tr></thead>
    <tbody>
    {% for p in providers %}
      {% for phase in phases %}
        {% if data[p][phase] and data[p][phase].third_party_domains %}
        <tr>
          <td class="provider-col">{{ p | title }}</td>
          <td class="phase-col">{{ phase.replace('_',' ') }}</td>
          <td>{% for domain in data[p][phase].third_party_domains %}{% set cat = data[p][phase].by_category_per_domain.get(domain, 'unknown_third_party') %}<span class="domain-entry"><span class="cat-dot cat-{{ cat }}"></span>{{ domain }}</span>{% endfor %}</td>
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

  <!-- PROVIDER PROFILES -->
  <div class="section-title" id="provider-profiles">Provider Profiles</div>
  <div class="two-col">
  {% for p in providers %}
  <div class="provider-card">
    <h3>{{ p | title }}</h3>
    {% for phase in phases %}
      {% if data[p][phase] %}
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.3px;color:#555;margin-top:8px;margin-bottom:4px;">{{ phase.replace('_',' ') }}</div>
      <div class="stat-row"><span class="stat-label">Total requests</span><span class="stat-value">{{ data[p][phase].total_requests }}</span></div>
      <div class="stat-row"><span class="stat-label">Unique domains</span><span class="stat-value">{{ data[p][phase].unique_domains }}</span></div>
      <div class="stat-row"><span class="stat-label">Third-party domains</span><span class="stat-value">{{ data[p][phase].third_party_domains | length }}</span></div>
      <div class="stat-row"><span class="stat-label">Email detections</span><span class="stat-value">{{ data[p][phase].get('email_leak_count', 0) }}</span></div>
      <div class="stat-row"><span class="stat-label">Browser noise filtered</span><span class="stat-value">{{ data[p][phase].get('browser_noise_requests_filtered', 0) }}</span></div>
      {% endif %}
    {% endfor %}
  </div>
  {% endfor %}
  </div>

  <!-- TRACKER TEST -->
  <div class="section-title" id="tracker-test">Tracker Test Results</div>
  <p class="note">A web bug (canary token tracking pixel) was embedded in an email and opened in each provider's client. The source IP that triggered the token reveals whether the provider proxies external image requests.</p>
  <table>
    <thead><tr>
      <th>Provider</th>
      <th>Token Fired</th>
      <th>Source IP Type</th>
      <th>Interpretation</th>
    </tr></thead>
    <tbody>
    <tr>
      <td style="font-weight:600;">Gmail</td>
      <td><span class="badge badge-green">Yes</span></td>
      <td>74.125.215.66 — Google Image Proxy</td>
      <td style="text-align:left;">Gmail fetched the image server-side via GoogleImageProxy. User IP not exposed to tracker. Google gains visibility into all external image URLs.</td>
    </tr>
    <tr>
      <td style="font-weight:600;">Outlook</td>
      <td><span class="badge badge-gray">Pending</span></td>
      <td>—</td>
      <td style="text-align:left;">—</td>
    </tr>
    <tr>
      <td style="font-weight:600;">ProtonMail</td>
      <td><span class="badge badge-gray">Pending</span></td>
      <td>—</td>
      <td style="text-align:left;">—</td>
    </tr>
    <tr>
      <td style="font-weight:600;">Tutanota</td>
      <td><span class="badge badge-gray">Pending</span></td>
      <td>—</td>
      <td style="text-align:left;">—</td>
    </tr>
    </tbody>
  </table>

  <!-- ENCRYPTION -->
  <div class="section-title" id="encryption">Encryption Assessment</div>
  <p class="note">Shannon entropy analysis of message content in active_usage captures. High entropy suggests encrypted content; low entropy suggests plaintext.</p>
  <table>
    <thead><tr><th>Provider</th><th>Phase</th><th>Verdict</th></tr></thead>
    <tbody>
    {% set any_verdict = [] %}
    {% for p in providers %}{% for phase in phases %}{% if verdicts[p][phase] %}{% set _ = any_verdict.append(1) %}
      <tr>
        <td style="font-weight:600;text-transform:capitalize;">{{ p }}</td>
        <td>{{ phase.replace('_',' ') | title }}</td>
        <td class="{{ 'verdict-good' if 'end-to-end encrypted' in verdicts[p][phase] else 'verdict-bad' }}">{{ verdicts[p][phase] }}</td>
      </tr>
    {% endif %}{% endfor %}{% endfor %}
    {% if not any_verdict %}<tr><td colspan="3" class="no-data">No encryption data yet — run encryption_checker.py on active_usage captures.</td></tr>{% endif %}
    </tbody>
  </table>

  <!-- LIMITATIONS -->
  <div class="section-title" id="limitations">Methodology Limitations</div>
  <div class="finding-box neutral">
    <div class="finding-label">Email leak detector scope</div>
    The classifier scans only the first 500 characters of each request body. Email addresses appearing beyond this limit are not detected, meaning the reported counts may be undercounts. Additionally, the detector matches any email-like pattern, not specifically the test account address, and does not distinguish between first-party and third-party destinations — manual verification of all flagged detections is required.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">VM snapshot isolation</div>
    Each experiment was run on a restored VM snapshot to ensure clean state. However, the VM used a shared network connection. Traffic from other devices on the same network is not captured, and the VM's IP address could in theory be linked to prior sessions by providers.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Browser noise filtering</div>
    Firefox background requests were filtered using a static domain list. This list may be incomplete — some Firefox traffic may remain in captures for providers whose experiments were run before the filter was implemented. ProtonMail idle captures in particular may include unfiltered browser noise.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Single experiment per phase</div>
    Each phase was run once per provider. Results represent a single observation and may not reflect typical behavior across multiple sessions or over time.
  </div>

  <div class="footer">Generated by email-privacy-tool &nbsp;·&nbsp; Northwestern University CS &nbsp;·&nbsp; {{ generated_at }}</div>
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
                if "email_leak_count" not in analysis:
                    analysis["email_leak_count"] = 0
                if "email_leaks" not in analysis:
                    analysis["email_leaks"] = []
                if "browser_noise_requests_filtered" not in analysis:
                    analysis["browser_noise_requests_filtered"] = 0
                if "total_request_size" not in analysis:
                    analysis["total_request_size"] = 0
                if "total_response_size" not in analysis:
                    analysis["total_response_size"] = 0
                analysis["by_category_per_domain"] = build_category_per_domain(analysis)
            data[provider][phase] = analysis
            verdicts[provider][phase] = load_encryption(provider, phase)

    template = Template(HTML_TEMPLATE)
    html = template.render(
        providers=PROVIDERS,
        phases=PHASES,
        data=data,
        verdicts=verdicts,
        phase_descriptions=PHASE_DESCRIPTIONS,
        generated_at=datetime.now().strftime("%B %d, %Y at %I:%M %p"),
    )

    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", "final_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
