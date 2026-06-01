#!/usr/bin/env python3
"""Generate a cross-provider HTML comparison report with deep CSV analysis."""

import csv
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

from jinja2 import Template

PROVIDERS = ["gmail", "yahoo", "protonmail", "tutanota"]
PHASES = ["account_creation", "idle", "active_usage", "tracker_test"]

PHASE_DESCRIPTIONS = {
    "account_creation": "Capture from first page load through completed account setup",
    "idle": "15 minutes with inbox open and no user interaction",
    "active_usage": "Composing, sending, and replying to email",
    "tracker_test": "Opening an email containing a web bug / canary token tracking pixel",
}

BROWSER_NOISE_DOMAINS = {
    "detectportal.firefox.com", "push.services.mozilla.com",
    "incoming.telemetry.mozilla.org", "firefox.settings.services.mozilla.com",
    "firefox-settings-attachments.cdn.mozilla.net", "aus5.mozilla.org",
    "content-signature-2.cdn.mozilla.net", "mozilla-ohttp.fastly-edge.com",
    "location.services.mozilla.com", "safebrowsing.googleapis.com",
    "prod.ohttp-gateway.prod.webservices.mozgcp.net", "ads-img.mozilla.org",
}

TRACKER_TEST_RESULTS = {
    "gmail": {
        "fired": True,
        "source_ip": "74.125.215.66",
        "source_type": "Google Image Proxy (ggpht.com)",
        "user_agent": "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)",
        "interpretation": "Gmail fetched the image server-side via GoogleImageProxy. User IP not exposed to tracker. Google gains visibility into all external image URLs in user emails.",
        "privacy_verdict": "mixed",
    },
    "yahoo": {"fired": None, "source_ip": None, "source_type": None, "user_agent": None, "interpretation": "Pending", "privacy_verdict": "unknown"},
    "protonmail": {"fired": None, "source_ip": None, "source_type": None, "user_agent": None, "interpretation": "Pending", "privacy_verdict": "unknown"},
    "tutanota": {"fired": None, "source_ip": None, "source_type": None, "user_agent": None, "interpretation": "Pending", "privacy_verdict": "unknown"},
}

# Plaintext patterns to search for in request body snippets
# Each entry: (label, pattern, severity, description)
PLAINTEXT_PATTERNS = [
    # Passwords
    ("password", r"Eptest2026!", "critical", "Test account password (Gmail/Yahoo)"),
    ("password", r"password123", "critical", "Test account password (ProtonMail/Tutanota)"),
    ("password", r"vboxuser", "high", "VM username"),
    # Usernames / account identifiers
    ("username", r"eptest", "high", "Test account username prefix"),
    ("username", r"vboxuser123", "high", "VM test account username"),
    # Email addresses — loose patterns for each test account
    ("email_address", r"eptest[\.\w]*@[\w\.]+", "high", "Test account email address"),
    # Email subject line words
    ("email_content", r"TEST\s*[-–]\s*(Andre|Daniel|Rishi|Ryan)", "high", "Test email subject line"),
    ("email_content", r"privacy\s+study", "medium", "Email body text"),
    ("email_content", r"test\s+email\s+for", "medium", "Email body text"),
    # Names
    ("personal_data", r"\bAndre\b", "medium", "Test account first name"),
    ("personal_data", r"\bWashington\b", "medium", "Test account last name"),
    ("personal_data", r"\bDaniel\b", "medium", "Team member name"),
    ("personal_data", r"\bRivero\b", "medium", "Team member last name"),
    ("personal_data", r"\bRishi\b", "medium", "Team member name"),
    ("personal_data", r"\bRyan\b", "medium", "Team member name"),
    ("personal_data", r"\bRosu\b", "medium", "Team member last name"),
    # Device / session identifiers
    ("device_info", r"Linux.*x86_64", "medium", "VM OS fingerprint in request body"),
    ("device_info", r"Ubuntu", "medium", "VM OS name in request body"),
    ("device_info", r"Firefox/\d+", "low", "Browser version in request body"),
    # Dates from test emails
    ("email_content", r"05[/\-\.](31|28|29|30)[/\-\.]2026", "medium", "Test email date"),
    # Session tokens / auth patterns (generic high-entropy strings in bodies going to third parties)
    ("session_data", r"authuser=\d", "low", "Auth user parameter"),
    ("session_data", r"gsessionid=[A-Za-z0-9_\-]+", "medium", "Google session ID in URL/body"),
]

POLICY_DATA = {
    "gmail": {
        "provider_name": "Gmail (Google)",
        "policy_url": "https://policies.google.com/privacy",
        "e2e_encryption": "No — transit encryption only (TLS). No end-to-end encryption mentioned anywhere in policy.",
        "third_parties_named": "No specific companies named. Categories only: affiliates, publishers, advertisers, developers, law enforcement.",
        "metadata_collected": "Yes — explicitly lists phone numbers, calling-party numbers, time/date, duration, routing info, and 'people with whom you communicate or share content.'",
        "jurisdiction": "United States. Complies with applicable law and enforceable governmental requests. No pushback language.",
        "vague_language": "Yes — 'depending on your available settings,' 'may also show you personalized ads,' 'in some circumstances.'",
        "explicit_negatives": "Does not show ads based on sensitive categories. Does not show ads based on Drive/Gmail/Photos content. Does not share personally identifying info with advertisers without consent.",
        "retention": "Four vague buckets — no actual timelines given for any data type.",
        "behavioral_data": "Yes — searches, videos watched, purchase activity, voice/audio, ad interactions, Chrome browsing history, activity on third-party sites.",
        "encryption_scope": "Mentions encryption only for data 'in transit.' No mention of subject lines, attachments, or recipient addresses.",
        "transparency_report": "Yes — publishes government request counts by type. One of the more specific and verifiable parts of the policy.",
        "empirical_contradictions": [
            "Policy claims no ads based on Gmail content — empirically contacts DoubleClick and Google Ads infrastructure during account creation before account exists",
            "Password transmitted in plaintext POST body — server-side access to credentials confirmed",
            "1157 requests during idle with no user interaction — behavioral telemetry collected passively",
        ],
    },
    "yahoo": {
        "provider_name": "Yahoo Mail",
        "policy_url": "https://legal.yahoo.com/us/en/yahoo/privacy/index.html",
        "e2e_encryption": "No — Microsoft-style server-side encryption only. No E2E offered to consumer users.",
        "third_parties_named": "Affiliates, trusted businesses, publishers, advertisers, developers, law enforcement. No specific companies named.",
        "metadata_collected": "Yes — traffic data including who you communicated with, when, location, device data.",
        "jurisdiction": "United States. Subject to FISA and national security orders. States no direct unfettered government access but consumer protections lower than enterprise.",
        "vague_language": "Yes — 'data we collect depends on the context of your interactions,' 'reasons such as operating effectively.'",
        "explicit_negatives": "Does not use human-to-human chat/call content or personal files to target ads.",
        "retention": "Vague buckets — no timelines. Data you delete, data retained for legal obligations, data deleted automatically.",
        "behavioral_data": "Yes — interests, favorites, content consumption, searches, browsing history, device/usage data, voice data, diagnostic data continuously.",
        "encryption_scope": "AES-256 at rest and in transit stated but no specification of which email components (subject, attachments, recipients) are covered.",
        "transparency_report": "Yes — government request reports for consumer data, biannual digital trust report. More useful for enterprise than consumer.",
        "empirical_contradictions": [
            "208 third-party domains contacted during account creation — massive undisclosed advertising ecosystem",
            "274 third-party cookies set during account creation",
            "193 third-party domains contacted during idle with zero user interaction",
            "Message content confirmed transmitted without E2E encryption via entropy analysis",
            "244 POST requests to third-party domains during account creation",
        ],
    },
    "protonmail": {
        "provider_name": "ProtonMail",
        "policy_url": "https://proton.me/legal/privacy",
        "e2e_encryption": "Yes for email content and attachments — but does not distinguish E2E from transit encryption in policy language. Subject lines, sender/recipient addresses encrypted without E2E.",
        "third_parties_named": "Yes — explicitly names Zendesk, Calendly, Stripe, PayPal, Chargebee, HubSpot, Atlassian, ProtonLabs with stated purpose for each.",
        "metadata_collected": "Yes — sender/recipient addresses, IP of incoming messages, attachment names, message subjects, send/receive times, number of messages, storage used, last login.",
        "jurisdiction": "Switzerland. Will comply with binding Swiss government requests. Past compliance with Swiss legal orders for user metadata.",
        "vague_language": "Yes — 'may collect certain technical information,' 'may use analytics software' in sections 2 and 3.",
        "explicit_negatives": "IP addresses not retained for analytics. No location tracking. ProtonScribe does not use data to train models. No data shared with third parties during Dark Web Monitoring.",
        "retention": "Vague 'temporary' storage without defining the period. Determined by 'legitimate interests' and Swiss legal requirements.",
        "behavioral_data": "Yes — number of messages sent, storage used, last login time, technical/crash data for service improvement.",
        "encryption_scope": "Body content and attachments E2E encrypted. Subject lines, recipient addresses, sender addresses encrypted without E2E — provider can see these.",
        "transparency_report": "Yes — required by Swiss law. Publishes number of Swiss government requests received, contested, and complied with.",
        "empirical_contradictions": [
            "Policy claims no third-party analytics — empirically contacted googleadservices.com and googletagmanager.com during account creation",
            "19 third-party domains during account creation including Sentry.io error tracking not mentioned in policy",
            "Policy claims IP not retained — but incoming message IP is explicitly listed as collected metadata",
            "Zero third-party contacts during active usage and tracker test — policy claims confirmed empirically",
        ],
    },
    "tutanota": {
        "provider_name": "Tutanota (Tuta)",
        "policy_url": "https://tuta.com/privacy-policy",
        "e2e_encryption": "Yes — claims E2E on all user data. But explicitly excludes necessary metadata stored unencrypted: user email addresses, sender/recipient addresses, email dates.",
        "third_parties_named": "Only PayPal and authorized credit institution for payment processing. Claims no other personal data disclosed to third parties.",
        "metadata_collected": "Yes — explicitly separates metadata from content. Email addresses, sender/recipient addresses, dates stored unencrypted. Content E2E encrypted.",
        "jurisdiction": "Germany / EU. Governed by GDPR. Can be legally bound to provide content and traffic data under valid court order.",
        "vague_language": "Mostly specific but includes 'unless specific reasons to the contrary apply in an individual case' and data 'may be stored' longer for complaints.",
        "explicit_negatives": "No cookies. No Google Analytics or third-party analysis tools. No personal data from third parties collected. No sale of data. Usage data not passed to third parties.",
        "retention": "Most specific of all providers — mail server logs max 7 days, personal data deleted within 30 days of contract termination, campaign data deleted within 30 days.",
        "behavioral_data": "Yes with consent — action sequences, time required for actions, abandonment points. Also geolocation and device types anonymized on own servers.",
        "encryption_scope": "All user data E2E encrypted except necessary metadata. Subject line encryption status not clearly specified in policy.",
        "transparency_report": "No transparency report mentioned in policy. Only states may be required to provide data under valid court order.",
        "empirical_contradictions": [
            "Policy explicitly claims 'we do not use analysis tools such as Google Analytics or other third-party tools' — empirically contacted googleadservices.com, googletagmanager.com, play.google.com during account creation",
            "Policy claims no personal data from third parties collected — but contacts Google advertising infrastructure",
            "Tutanota emails landed in Gmail spam — possible DKIM/SPF/DMARC weakness",
            "Zero third-party contacts during idle — policy claims confirmed empirically",
        ],
    },
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
    .four-col { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 1.5rem; margin-bottom: 1rem; }
    .provider-card { border: 1px solid #e8e8e8; padding: 12px; }
    .provider-card h3 { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #e8e8e8; padding-bottom: 6px; margin-bottom: 8px; }
    .stat-row { display: flex; justify-content: space-between; font-size: 10px; padding: 2px 0; border-bottom: 1px solid #f0f0f0; }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: #555; }
    .stat-value { font-weight: 600; }
    .phase-desc { font-size: 10px; color: #666; font-style: italic; margin-bottom: 0.5rem; }
    .toc { margin: 1rem 0 2rem; font-size: 11px; }
    .toc a { color: #000; text-decoration: none; display: block; padding: 2px 0; border-bottom: 1px dotted #ddd; }
    .toc a:hover { text-decoration: underline; }
    .toc-section { font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 8px; margin-bottom: 2px; color: #555; }
    .badge { display: inline-block; font-size: 9px; font-weight: 700; padding: 1px 5px; border-radius: 2px; text-transform: uppercase; letter-spacing: 0.3px; }
    .badge-red { background: #fee2e2; color: #b91c1c; }
    .badge-green { background: #dcfce7; color: #15803d; }
    .badge-gray { background: #f3f4f6; color: #6b7280; }
    .badge-yellow { background: #fef9c3; color: #854d0e; }
    .badge-orange { background: #ffedd5; color: #c2410c; }
    summary { cursor: pointer; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 4px 0; }
    details { margin: 4px 0; border: 1px solid #e8e8e8; padding: 4px 8px; }
    .note { font-size: 10px; color: #666; font-style: italic; margin: 4px 0 8px; }
    code { font-family: monospace; font-size: 10px; background: #f3f4f6; padding: 1px 4px; border-radius: 2px; }
    .highlight { background: #fef9c3; padding: 1px 3px; border-radius: 2px; font-family: monospace; font-size: 10px; }
    .bar-wrap { display: flex; align-items: center; gap: 6px; }
    .bar-fill { height: 10px; background: #111; display: inline-block; min-width: 1px; }
    .bar-fill.gmail { background: #4285f4; }
    .bar-fill.yahoo { background: #6001d2; }
    .bar-fill.protonmail { background: #6d4aff; }
    .bar-fill.tutanota { background: #c20000; }
    .bar-val { font-size: 10px; color: #333; }
    .plaintext-hit { background: #fff7ed; border: 1px solid #fed7aa; padding: 6px 10px; margin: 3px 0; font-size: 10px; border-radius: 2px; }
    .plaintext-hit .hit-label { font-weight: 700; color: #c2410c; font-size: 9px; text-transform: uppercase; letter-spacing: 0.3px; }
    .plaintext-hit .hit-context { font-family: monospace; font-size: 10px; color: #111; word-break: break-all; margin-top: 2px; }
    .plaintext-hit .hit-meta { font-size: 9px; color: #666; margin-top: 2px; }
    .severity-critical { color: #b91c1c; font-weight: 700; }
    .severity-high { color: #c2410c; font-weight: 700; }
    .severity-medium { color: #b45309; }
    .severity-low { color: #6b7280; }
    .policy-table td { text-align: left !important; vertical-align: top; font-size: 10px; line-height: 1.5; }
    .policy-table th { text-align: left !important; }
    .contradiction { background: #fee2e2; border-left: 3px solid #b91c1c; padding: 4px 8px; margin: 2px 0; font-size: 10px; }
    .confirmed { background: #dcfce7; border-left: 3px solid #15803d; padding: 4px 8px; margin: 2px 0; font-size: 10px; }
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
    <a href="#method-breakdown">HTTP Method Breakdown</a>
    <a href="#post-analysis">POST Request Analysis</a>
    <a href="#status-codes">HTTP Status Code Distribution</a>
    <a href="#content-types">Content Type Distribution</a>
    <a href="#cookies">Cookie Analysis</a>
    <a href="#data-volume">Data Volume</a>
    <a href="#third-party-js">Third-Party JavaScript</a>
    <a href="#timing">Time to First Third-Party Request</a>
    <div class="toc-section">Plaintext &amp; Personal Data Analysis</div>
    <a href="#plaintext">Plaintext Personal Data in Request Bodies</a>
    <a href="#email-leaks">Email Address Leak Detection</a>
    <div class="toc-section">Domain Analysis</div>
    <a href="#top-domains">Top Domains by Request Count</a>
    <a href="#top-third-party">Top Third-Party Domains by Request Count</a>
    <a href="#persistent-trackers">Persistent Trackers Across Phases</a>
    <a href="#domain-breakdown">Full Third-Party Domain Breakdown</a>
    <div class="toc-section">Qualitative Analysis</div>
    <a href="#policy-comparison">Privacy Policy vs Empirical Findings</a>
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
    <div class="finding-label">Yahoo has massive advertising infrastructure</div>
    Yahoo contacted 208 third-party domains during account creation and tracker test — 40x more than Gmail (5) and 16x more than ProtonMail (13). During idle, Yahoo contacted 193 third-party domains with no user interaction, compared to Gmail's 10. Yahoo set 274 third-party cookies during account creation and sent 244 POST requests to third-party domains.
  </div>
  <div class="finding-box negative">
    <div class="finding-label">Gmail idle activity</div>
    Gmail generated 1,157 requests and contacted 10 third-party domains during 15 minutes of zero user interaction — more traffic than during account creation. Google Analytics, Tag Manager, and four DoubleClick subdomains were active with no user activity.
  </div>
  <div class="finding-box negative">
    <div class="finding-label">Password and personal data in plaintext request bodies</div>
    The test account password (Eptest2026!) was found in plaintext in a POST request body during Gmail account creation. Additional personal identifiers including usernames, email addresses, and test email content were found in request bodies across multiple providers. All were protected by TLS in transit but readable by the receiving server.
  </div>
  <div class="finding-box negative">
    <div class="finding-label">Privacy providers contact Google infrastructure</div>
    Both ProtonMail and Tutanota contacted Google advertising infrastructure (googleadservices.com, googletagmanager.com) during account creation, despite marketing themselves as Google alternatives. Tutanota's own privacy policy explicitly claims they do not use Google Analytics or third-party tools — a direct empirical contradiction.
  </div>
  <div class="finding-box positive">
    <div class="finding-label">ProtonMail active usage contacts zero third-party domains</div>
    ProtonMail made only 1 third-party request during active email use — push.services.mozilla.com, which is Firefox browser noise. ProtonMail itself contacted zero third-party services while sending and receiving email.
  </div>
  <div class="finding-box positive">
    <div class="finding-label">Tutanota idle is remarkably clean</div>
    Tutanota generated only 40 requests and contacted 1 domain during idle — 29x fewer requests than Gmail. The single domain contacted was its own first-party API.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Gmail proxies tracking pixels</div>
    When a canary token web bug was opened in Gmail, the request came from IP 74.125.215.66 (Google Image Proxy) rather than the user's IP. Gmail protects users from third-party IP tracking but gains visibility into all external image URLs.
  </div>
  <div class="finding-box positive">
    <div class="finding-label">ProtonMail encryption confirmed</div>
    Entropy analysis confirmed ProtonMail message content is end-to-end encrypted via PGP. Yahoo was confirmed as transmitting message content without end-to-end encryption.
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
    <thead><tr><th>Category</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% set cats = ['first_party', 'advertising', 'analytics', 'known_tracker', 'unknown_third_party'] %}
    {% for cat in cats %}
    <tr>
      <td><span class="cat-dot cat-{{ cat }}"></span>{{ cat.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>{% if data[p][phase] %}{{ data[p][phase].get('by_category', {}).get(cat, 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endfor %}

  <!-- HTTP METHOD BREAKDOWN -->
  <div class="section-title" id="method-breakdown">HTTP Method Breakdown</div>
  <p class="note">GET requests fetch resources; POST requests send data. A higher POST ratio indicates more data being uploaded to servers.</p>
  {% for phase in phases %}
  <div class="subsection-title">{{ phase.replace('_',' ') | title }}</div>
  <table>
    <thead><tr><th>Method</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for method in ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'] %}
    <tr>
      <td><code>{{ method }}</code></td>
      {% for p in providers %}
      <td>{% if deep[p][phase] %}{{ deep[p][phase].get('method_breakdown', {}).get(method, 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endfor %}

  <!-- POST REQUEST ANALYSIS -->
  <div class="section-title" id="post-analysis">POST Request Analysis</div>
  <p class="note">POST requests send data to servers. POST requests with non-empty bodies contain user or session data being uploaded. POST requests to third-party domains are particularly privacy-relevant.</p>
  <table>
    <thead><tr><th>Metric</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label" colspan="{{ providers|length + 1 }}" style="text-align:left;background:#f7f7f7;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">{{ phase.replace('_',' ') | title }}</td>
    </tr>
    <tr>
      <td>Total POST requests</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('post_request_count', 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>POST with non-empty body</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('post_with_body_count', 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>POST to third-party domains</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('post_third_party_count', 0) %}{% if v > 0 %}<span class="high">{{ v }}</span>{% else %}0{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% for p in providers %}{% for phase in phases %}{% if deep[p][phase] and deep[p][phase].get('post_third_party_examples') %}
  <details>
    <summary>{{ p | title }} {{ phase.replace('_',' ') }} — POST to third-party examples</summary>
    <table style="margin-top:6px;">
      <thead><tr><th style="text-align:left;">Host</th><th style="text-align:left;">Path</th><th style="text-align:left;">Body snippet</th></tr></thead>
      <tbody>
      {% for ex in deep[p][phase].post_third_party_examples %}
      <tr>
        <td style="text-align:left;font-family:monospace;font-size:10px;">{{ ex.host }}</td>
        <td style="text-align:left;font-family:monospace;font-size:10px;">{{ ex.path }}</td>
        <td style="text-align:left;font-family:monospace;font-size:10px;word-break:break-all;">{{ ex.body[:100] }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </details>
  {% endif %}{% endfor %}{% endfor %}

  <!-- STATUS CODES -->
  <div class="section-title" id="status-codes">HTTP Status Code Distribution</div>
  <p class="note">2xx = success, 3xx = redirect, 4xx = client error, 5xx = server error. High redirect counts can indicate tracking chains.</p>
  {% for phase in phases %}
  <div class="subsection-title">{{ phase.replace('_',' ') | title }}</div>
  <table>
    <thead><tr><th>Status</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for code in ['200', '204', '301', '302', '304', '400', '403', '404'] %}
    <tr>
      <td><code>{{ code }}</code></td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('status_code_breakdown', {}).get(code, 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    <tr>
      <td>Total redirects (3xx)</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('redirect_count', 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    </tbody>
  </table>
  {% endfor %}

  <!-- CONTENT TYPES -->
  <div class="section-title" id="content-types">Content Type Distribution</div>
  <p class="note">Shows what kinds of resources are being loaded. Heavy JavaScript loading from third parties is a tracker signal.</p>
  {% for phase in phases %}
  <div class="subsection-title">{{ phase.replace('_',' ') | title }}</div>
  <table>
    <thead><tr><th>Content Type</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for ct in ['javascript', 'json', 'html', 'image', 'font', 'css', 'text/plain', 'binary'] %}
    <tr>
      <td><code>{{ ct }}</code></td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('content_type_breakdown', {}).get(ct, 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endfor %}

  <!-- COOKIES -->
  <div class="section-title" id="cookies">Cookie Analysis</div>
  <p class="note">Third-party cookies set by non-provider domains are used for cross-site tracking. More third-party cookies = more tracking infrastructure.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label" colspan="{{ providers|length + 1 }}" style="text-align:left;background:#f7f7f7;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">{{ phase.replace('_',' ') | title }}</td>
    </tr>
    <tr>
      <td>Total cookies set</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{{ deep[p][phase].get('total_cookies_set', 0) }}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>Third-party cookies set</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('third_party_cookies_set', 0) %}{% if v > 0 %}<span class="high">{{ v }}</span>{% else %}<span class="low">0</span>{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% for p in providers %}{% for phase in phases %}{% if deep[p][phase] and deep[p][phase].get('third_party_cookie_domains') %}
  <details>
    <summary>{{ p | title }} {{ phase.replace('_',' ') }} — third-party cookie domains</summary>
    <p style="font-size:10px;padding:6px 0;">{{ deep[p][phase].third_party_cookie_domains | join(' · ') }}</p>
  </details>
  {% endif %}{% endfor %}{% endfor %}

  <!-- DATA VOLUME -->
  <div class="section-title" id="data-volume">Data Volume</div>
  <p class="note">Total bytes transferred per phase. Third-party bytes show how much data was sent to/received from non-provider servers.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label" colspan="{{ providers|length + 1 }}" style="text-align:left;background:#f7f7f7;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">{{ phase.replace('_',' ') | title }}</td>
    </tr>
    <tr>
      <td>Total data (KB)</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('total_bytes', 0) %}{% if v > 0 %}{{ "%.1f"|format(v/1024) }}{% else %}—{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>Sent to servers (KB)</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('total_request_bytes', 0) %}{% if v > 0 %}{{ "%.1f"|format(v/1024) }}{% else %}—{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>Received from servers (KB)</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('total_response_bytes', 0) %}{% if v > 0 %}{{ "%.1f"|format(v/1024) }}{% else %}—{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    <tr>
      <td>Third-party data (KB)</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('third_party_total_bytes', 0) %}{% if v > 0 %}<span class="high">{{ "%.1f"|format(v/1024) }}</span>{% else %}<span class="low">0</span>{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- THIRD PARTY JS -->
  <div class="section-title" id="third-party-js">Third-Party JavaScript</div>
  <p class="note">JavaScript loaded from third-party domains executes in the browser and can collect data, track behavior, and fingerprint users.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}<td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('third_party_js_count', 0) %}{% if v > 5 %}<span class="high">{{ v }}</span>{% elif v > 0 %}<span class="mid">{{ v }}</span>{% else %}<span class="low">0</span>{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>{% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% for p in providers %}{% for phase in phases %}{% if deep[p][phase] and deep[p][phase].get('third_party_js_domains') %}
  <details>
    <summary>{{ p | title }} {{ phase.replace('_',' ') }} — third-party JS sources</summary>
    <p style="font-size:10px;padding:6px 0;">{{ deep[p][phase].third_party_js_domains | join(' · ') }}</p>
  </details>
  {% endif %}{% endfor %}{% endfor %}

  <!-- TIMING -->
  <div class="section-title" id="timing">Time to First Third-Party Request</div>
  <p class="note">How many seconds after the first captured request before a third-party domain was contacted. Lower = trackers load sooner.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>{% if deep[p][phase] %}{% set v = deep[p][phase].get('seconds_to_first_third_party') %}{% if v is not none %}{{ v }}s{% else %}<span class="missing">—</span>{% endif %}{% else %}<span class="missing">—</span>{% endif %}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- PLAINTEXT PERSONAL DATA -->
  <div class="section-title" id="plaintext">Plaintext Personal Data in Request Bodies</div>
  <p class="note">
    Scan of all captured request body snippets for personally identifiable information, credentials, and email content transmitted in readable form.
    All matches are protected by TLS in transit, meaning only the receiving server can read them — but this confirms those servers have access to this data.
    Note: mitmproxy truncates request bodies to 500 characters. Data appearing beyond that limit is not detectable here.
  </p>
  {% set total_hits = [] %}
  {% for p in providers %}{% for phase in phases %}{% if plaintext[p][phase] %}{% for hit in plaintext[p][phase] %}{% set _ = total_hits.append(1) %}{% endfor %}{% endif %}{% endfor %}{% endfor %}
  <p style="font-size:11px;margin-bottom:1rem;">Total plaintext detections across all providers and phases: <strong>{{ total_hits | length }}</strong></p>

  <!-- Summary table -->
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if plaintext[p][phase] %}
          {% set n = plaintext[p][phase] | length %}
          {% if n > 0 %}<span class="high">{{ n }}</span>{% else %}<span class="low">0</span>{% endif %}
        {% else %}<span class="low">0</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- Detailed hits by provider/phase -->
  {% for p in providers %}
    {% for phase in phases %}
      {% if plaintext[p][phase] %}
      <details>
        <summary>{{ p | title }} — {{ phase.replace('_',' ') | title }} — {{ plaintext[p][phase] | length }} detection(s)</summary>
        <div style="margin-top:6px;">
        {% for hit in plaintext[p][phase] %}
        <div class="plaintext-hit">
          <div class="hit-label">
            <span class="severity-{{ hit.severity }}">{{ hit.severity | upper }}</span>
            &nbsp;·&nbsp; {{ hit.category | upper }}
            &nbsp;·&nbsp; {{ hit.description }}
          </div>
          <div class="hit-context">Pattern matched: <span class="highlight">{{ hit.matched }}</span></div>
          <div class="hit-meta">
            Host: <code>{{ hit.host }}</code> &nbsp;·&nbsp;
            Path: <code>{{ hit.path[:60] }}</code> &nbsp;·&nbsp;
            Category: <code>{{ hit.domain_category }}</code> &nbsp;·&nbsp;
            Method: <code>{{ hit.method }}</code>
          </div>
          <div class="hit-meta" style="margin-top:3px;">
            Context: <code style="word-break:break-all;">{{ hit.context }}</code>
          </div>
        </div>
        {% endfor %}
        </div>
      </details>
      {% endif %}
    {% endfor %}
  {% endfor %}

  <!-- EMAIL LEAKS -->
  <div class="section-title" id="email-leaks">Email Address Leak Detection</div>
  <p class="note">Regex scan of request body snippets for email address patterns. Requires manual verification — counts include legitimate first-party API calls.</p>
  <table>
    <thead><tr><th>Phase</th>{% for p in providers %}<th>{{ p | title }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for phase in phases %}
    <tr>
      <td class="phase-label">{{ phase.replace('_',' ') | title }}</td>
      {% for p in providers %}
      <td>
        {% if data[p][phase] %}
          {% set lc = data[p][phase].get('email_leak_count', 0) %}
          {% if lc > 0 %}<span class="leak-yes">{{ lc }}</span>{% else %}<span class="leak-no">0</span>{% endif %}
        {% else %}<span class="missing">—</span>{% endif %}
      </td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% for p in providers %}{% for phase in phases %}{% if data[p][phase] and data[p][phase].get('email_leaks') %}
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
          {% if 'tuta.com' in leak.host or 'proton' in leak.host or 'gmail' in leak.host or 'yahoo' in leak.host %}
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
  {% endif %}{% endfor %}{% endfor %}

  <!-- TOP DOMAINS BY COUNT -->
  <div class="section-title" id="top-domains">Top Domains by Request Count</div>
  <p class="note">Most frequently contacted domains across all request types per provider and phase.</p>
  {% for p in providers %}
  <div class="subsection-title">{{ p | title }}</div>
  {% for phase in phases %}{% if deep[p][phase] and deep[p][phase].get('top_domains_by_count') %}
  <details>
    <summary>{{ phase.replace('_',' ') | title }}</summary>
    <table style="margin-top:6px;">
      <thead><tr><th style="text-align:left;">Domain</th><th>Requests</th></tr></thead>
      <tbody>
      {% for domain, count in deep[p][phase].top_domains_by_count %}
      <tr>
        <td style="text-align:left;font-family:monospace;font-size:10px;">{{ domain }}</td>
        <td><div class="bar-wrap"><div class="bar-fill {{ p }}" style="width:{{ [count * 2, 200] | min }}px;"></div><span class="bar-val">{{ count }}</span></div></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </details>
  {% endif %}{% endfor %}
  {% endfor %}

  <!-- TOP THIRD-PARTY DOMAINS BY COUNT -->
  <div class="section-title" id="top-third-party">Top Third-Party Domains by Request Count</div>
  <p class="note">Most frequently contacted third-party domains — high counts indicate persistent tracking, not just one-time resource loads.</p>
  {% for p in providers %}
  <div class="subsection-title">{{ p | title }}</div>
  {% for phase in phases %}{% if deep[p][phase] and deep[p][phase].get('top_third_party_domains_by_count') %}
  <details>
    <summary>{{ phase.replace('_',' ') | title }}</summary>
    <table style="margin-top:6px;">
      <thead><tr><th style="text-align:left;">Domain</th><th>Requests</th></tr></thead>
      <tbody>
      {% for domain, count in deep[p][phase].top_third_party_domains_by_count %}
      <tr>
        <td style="text-align:left;font-family:monospace;font-size:10px;">{{ domain }}</td>
        <td><div class="bar-wrap"><div class="bar-fill {{ p }}" style="width:{{ [count * 4, 200] | min }}px;"></div><span class="bar-val">{{ count }}</span></div></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </details>
  {% endif %}{% endfor %}
  {% endfor %}

  <!-- PERSISTENT TRACKERS -->
  <div class="section-title" id="persistent-trackers">Persistent Trackers Across Phases</div>
  <p class="note">Third-party domains that appeared in two or more phases for the same provider. These are persistent tracking relationships, not just signup-time trackers.</p>
  <div class="four-col">
  {% for p in providers %}
  <div class="provider-card">
    <h3>{{ p | title }}</h3>
    {% if persistent[p] %}
      {% for domain, phases in persistent[p].items() %}
      <div style="font-size:10px;margin-bottom:4px;">
        <code>{{ domain }}</code><br>
        <span style="color:#666;">{{ phases | join(', ') | replace('_',' ') }}</span>
      </div>
      {% endfor %}
    {% else %}
      <span class="no-data">No persistent third-party trackers detected</span>
    {% endif %}
  </div>
  {% endfor %}
  </div>

  <!-- DOMAIN BREAKDOWN -->
  <div class="section-title" id="domain-breakdown">Full Third-Party Domain Breakdown by Provider</div>
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
    <thead><tr><th>Provider</th><th>Phase</th><th>Count</th><th>Third-party domains</th></tr></thead>
    <tbody>
    {% for p in providers %}{% for phase in phases %}
      {% if data[p][phase] and data[p][phase].third_party_domains %}
      <tr>
        <td class="provider-col">{{ p | title }}</td>
        <td class="phase-col">{{ phase.replace('_',' ') }}</td>
        <td>{{ data[p][phase].third_party_domains | length }}</td>
        <td>{% for domain in data[p][phase].third_party_domains %}{% set cat = data[p][phase].by_category_per_domain.get(domain, 'unknown_third_party') %}<span class="domain-entry"><span class="cat-dot cat-{{ cat }}"></span>{{ domain }}</span>{% endfor %}</td>
      </tr>
      {% elif data[p][phase] %}
      <tr>
        <td class="provider-col">{{ p | title }}</td>
        <td class="phase-col">{{ phase.replace('_',' ') }}</td>
        <td>0</td>
        <td class="no-data">none detected</td>
      </tr>
      {% endif %}
    {% endfor %}{% endfor %}
    </tbody>
  </table>

  <!-- POLICY COMPARISON -->
  <div class="section-title" id="policy-comparison">Privacy Policy vs Empirical Findings</div>
  <p class="note">Direct comparison of what each provider claims in their privacy policy against what was empirically observed in network captures. Contradictions are highlighted in red; confirmed claims in green.</p>

  {% for p in providers %}
  {% set pol = policy[p] %}
  <div class="subsection-title">{{ pol.provider_name }} &nbsp;<a href="{{ pol.policy_url }}" style="font-weight:400;font-size:9px;color:#555;">{{ pol.policy_url }}</a></div>
  <table class="policy-table" style="margin-bottom:1rem;">
    <thead><tr><th style="width:180px;">Question</th><th>Policy Claim</th></tr></thead>
    <tbody>
    <tr>
      <td style="font-weight:700;">End-to-end encryption</td>
      <td>{{ pol.e2e_encryption }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Third parties named</td>
      <td>{{ pol.third_parties_named }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Metadata collection</td>
      <td>{{ pol.metadata_collected }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Jurisdiction &amp; legal requests</td>
      <td>{{ pol.jurisdiction }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Vague language</td>
      <td>{{ pol.vague_language }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Explicit negatives</td>
      <td>{{ pol.explicit_negatives }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Data retention</td>
      <td>{{ pol.retention }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Behavioral data</td>
      <td>{{ pol.behavioral_data }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Encryption scope</td>
      <td>{{ pol.encryption_scope }}</td>
    </tr>
    <tr>
      <td style="font-weight:700;">Transparency report</td>
      <td>{{ pol.transparency_report }}</td>
    </tr>
    </tbody>
  </table>
  <div style="margin-bottom:1.5rem;">
    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Empirical contradictions &amp; confirmations</div>
    {% for item in pol.empirical_contradictions %}
    {% if 'confirmed' in item.lower() or 'zero' in item.lower() or 'clean' in item.lower() %}
    <div class="confirmed">✓ {{ item }}</div>
    {% else %}
    <div class="contradiction">✗ {{ item }}</div>
    {% endif %}
    {% endfor %}
  </div>
  {% endfor %}

  <!-- PROVIDER PROFILES -->
  <div class="section-title" id="provider-profiles">Provider Profiles</div>
  <div class="two-col">
  {% for p in providers %}
  <div class="provider-card">
    <h3>{{ p | title }}</h3>
    {% for phase in phases %}{% if data[p][phase] %}
    <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.3px;color:#555;margin-top:8px;margin-bottom:4px;">{{ phase.replace('_',' ') }}</div>
    <div class="stat-row"><span class="stat-label">Total requests</span><span class="stat-value">{{ data[p][phase].total_requests }}</span></div>
    <div class="stat-row"><span class="stat-label">Unique domains</span><span class="stat-value">{{ data[p][phase].unique_domains }}</span></div>
    <div class="stat-row"><span class="stat-label">Third-party domains</span><span class="stat-value">{{ data[p][phase].third_party_domains | length }}</span></div>
    <div class="stat-row"><span class="stat-label">POST requests</span><span class="stat-value">{% if deep[p][phase] %}{{ deep[p][phase].get('post_request_count', 0) }}{% else %}—{% endif %}</span></div>
    <div class="stat-row"><span class="stat-label">POST to third parties</span><span class="stat-value">{% if deep[p][phase] %}{{ deep[p][phase].get('post_third_party_count', 0) }}{% else %}—{% endif %}</span></div>
    <div class="stat-row"><span class="stat-label">Third-party cookies set</span><span class="stat-value">{% if deep[p][phase] %}{{ deep[p][phase].get('third_party_cookies_set', 0) }}{% else %}—{% endif %}</span></div>
    <div class="stat-row"><span class="stat-label">Third-party JS files</span><span class="stat-value">{% if deep[p][phase] %}{{ deep[p][phase].get('third_party_js_count', 0) }}{% else %}—{% endif %}</span></div>
    <div class="stat-row"><span class="stat-label">Plaintext detections</span><span class="stat-value">{% if plaintext[p][phase] %}{{ plaintext[p][phase] | length }}{% else %}0{% endif %}</span></div>
    <div class="stat-row"><span class="stat-label">Email detections</span><span class="stat-value">{{ data[p][phase].get('email_leak_count', 0) }}</span></div>
    <div class="stat-row"><span class="stat-label">Browser noise filtered</span><span class="stat-value">{{ data[p][phase].get('browser_noise_requests_filtered', 0) }}</span></div>
    {% endif %}{% endfor %}
  </div>
  {% endfor %}
  </div>

  <!-- TRACKER TEST -->
  <div class="section-title" id="tracker-test">Tracker Test Results</div>
  <p class="note">A web bug (canary token tracking pixel) was embedded in an email and opened in each provider's client. The source IP that triggered the token reveals whether the provider proxies external image requests.</p>
  <table>
    <thead><tr><th>Provider</th><th>Token Fired</th><th>Source IP</th><th>User Agent</th><th style="text-align:left;">Interpretation</th></tr></thead>
    <tbody>
    {% for p in providers %}{% set tr = tracker_results[p] %}
    <tr>
      <td style="font-weight:600;text-transform:capitalize;">{{ p }}</td>
      <td>{% if tr.fired == true %}<span class="badge badge-green">Yes</span>{% elif tr.fired == false %}<span class="badge badge-red">No</span>{% else %}<span class="badge badge-gray">Pending</span>{% endif %}</td>
      <td><code>{% if tr.source_ip %}{{ tr.source_ip }}{% else %}—{% endif %}</code></td>
      <td style="font-size:9px;font-family:monospace;max-width:200px;word-break:break-all;">{% if tr.user_agent %}{{ tr.user_agent[:80] }}{% else %}—{% endif %}</td>
      <td style="text-align:left;">{{ tr.interpretation }}</td>
    </tr>
    {% endfor %}
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
    <div class="finding-label">Request body truncation</div>
    mitmproxy truncates request bodies to 500 characters before saving to CSV. Plaintext data appearing beyond the 500-character mark in a request body is undetectable in this analysis. All plaintext detections reported here are confirmed findings; absence of detection does not confirm absence of plaintext data.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Email leak detector scope</div>
    The classifier scans only the first 500 characters of each request body. The detector matches any email-like pattern, not specifically the test account address, and does not distinguish between first-party and third-party destinations.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">VM snapshot isolation</div>
    Each experiment was run on a restored VM snapshot to ensure clean state. However, the VM used a shared network connection. The VM's IP address could in theory be linked to prior sessions by providers.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Browser noise filtering</div>
    Firefox background requests were filtered using a static domain list. This list may be incomplete — some Firefox traffic may remain in captures for providers whose experiments were run before the filter was implemented.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Single experiment per phase</div>
    Each phase was run once per provider. Results represent a single observation and may not reflect typical behavior across multiple sessions or over time.
  </div>
  <div class="finding-box neutral">
    <div class="finding-label">Data volume figures</div>
    Request and response size fields in the CSV may be 0 for some captures depending on the version of the capture script used.
  </div>

  <div class="footer">Generated by email-privacy-tool &nbsp;·&nbsp; Northwestern University CS &nbsp;·&nbsp; {{ generated_at }}</div>
</body>
</html>
"""


def scan_plaintext(rows, provider: str) -> list:
    """Scan all request body snippets for plaintext personal data patterns."""
    hits = []
    if not rows:
        return hits

    compiled = [(label, re.compile(pattern, re.IGNORECASE), severity, desc)
                for label, pattern, severity, desc in PLAINTEXT_PATTERNS]

    for row in rows:
        body = row.get("request_body_snippet", "") or ""
        if not body.strip():
            continue

        host = row.get("host", "")
        path = row.get("path", "")
        method = row.get("method", "").upper()
        domain_category = row.get("category", "unknown")

        for label, pattern, severity, desc in compiled:
            match = pattern.search(body)
            if match:
                # Get context around match
                start = max(0, match.start() - 30)
                end = min(len(body), match.end() + 30)
                context = body[start:end].replace("\n", " ").replace("\r", " ")

                hits.append({
                    "category": label,
                    "description": desc,
                    "severity": severity,
                    "matched": match.group(0)[:80],
                    "context": context[:150],
                    "host": host,
                    "path": path[:80],
                    "method": method,
                    "domain_category": domain_category,
                    "is_third_party": domain_category not in ("first_party", "browser_noise", ""),
                })

    # Deduplicate — same pattern + host + path
    seen = set()
    deduped = []
    for h in hits:
        key = (h["category"], h["matched"][:20], h["host"], h["path"][:30])
        if key not in seen:
            seen.add(key)
            deduped.append(h)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduped.sort(key=lambda x: severity_order.get(x["severity"], 4))
    return deduped


def deep_analyze_csv(rows, provider: str) -> dict:
    if not rows:
        return {}

    result = {}

    def simplify_ct(ct):
        ct = ct.split(";")[0].strip().lower()
        if not ct:
            return "unknown"
        if "javascript" in ct:
            return "javascript"
        if "json" in ct:
            return "json"
        if "html" in ct:
            return "html"
        if "css" in ct:
            return "css"
        if "font" in ct or "woff" in ct:
            return "font"
        if "image" in ct:
            return "image"
        if "text/plain" in ct:
            return "text/plain"
        if "binary" in ct or "octet" in ct:
            return "binary"
        return ct[:30]

    methods = Counter(r.get("method", "").upper() for r in rows)
    result["method_breakdown"] = dict(methods.most_common())

    codes = Counter(r.get("status_code", "") for r in rows)
    result["status_code_breakdown"] = dict(codes.most_common(10))

    cts = Counter(simplify_ct(r.get("content_type", "")) for r in rows)
    result["content_type_breakdown"] = dict(cts.most_common(10))

    domain_counts = Counter(r.get("host", "") for r in rows if r.get("host"))
    result["top_domains_by_count"] = domain_counts.most_common(15)

    third_party_counts = Counter(
        r.get("host", "") for r in rows
        if r.get("category", "") not in ("first_party", "browser_noise", "")
        and r.get("host", "") not in BROWSER_NOISE_DOMAINS
    )
    result["top_third_party_domains_by_count"] = third_party_counts.most_common(10)

    post_rows = [r for r in rows if r.get("method", "").upper() == "POST"]
    result["post_request_count"] = len(post_rows)
    result["get_request_count"] = sum(1 for r in rows if r.get("method", "").upper() == "GET")
    result["post_with_body_count"] = sum(1 for r in post_rows if r.get("request_body_snippet", "").strip())

    post_third_party = [
        r for r in post_rows
        if r.get("category", "") not in ("first_party", "browser_noise", "")
        and r.get("host", "") not in BROWSER_NOISE_DOMAINS
    ]
    result["post_third_party_count"] = len(post_third_party)
    result["post_third_party_examples"] = [
        {"host": r.get("host", ""), "path": r.get("path", "")[:80], "body": r.get("request_body_snippet", "")[:120]}
        for r in post_third_party[:5]
    ]

    cookies_set = [r for r in rows if r.get("set_cookies", "").strip()]
    result["total_cookies_set"] = len(cookies_set)
    third_party_cookies = [
        r for r in cookies_set
        if r.get("category", "") not in ("first_party", "browser_noise", "")
        and r.get("host", "") not in BROWSER_NOISE_DOMAINS
    ]
    result["third_party_cookies_set"] = len(third_party_cookies)
    result["third_party_cookie_domains"] = list({r.get("host", "") for r in third_party_cookies})[:10]

    total_req = total_resp = tp_req = tp_resp = 0
    for r in rows:
        try:
            rq = int(r.get("request_size", 0) or 0)
            rs = int(r.get("response_size", 0) or 0)
        except (ValueError, TypeError):
            rq = rs = 0
        total_req += rq
        total_resp += rs
        if r.get("category", "") not in ("first_party", "browser_noise", "") and r.get("host", "") not in BROWSER_NOISE_DOMAINS:
            tp_req += rq
            tp_resp += rs

    result["total_request_bytes"] = total_req
    result["total_response_bytes"] = total_resp
    result["total_bytes"] = total_req + total_resp
    result["third_party_request_bytes"] = tp_req
    result["third_party_response_bytes"] = tp_resp
    result["third_party_total_bytes"] = tp_req + tp_resp

    first_tp_time = first_request_time = None
    for r in rows:
        ts = r.get("timestamp", "")
        if not ts:
            continue
        try:
            t = datetime.fromisoformat(ts)
            if first_request_time is None:
                first_request_time = t
            if (r.get("category", "") not in ("first_party", "browser_noise", "")
                    and r.get("host", "") not in BROWSER_NOISE_DOMAINS
                    and first_tp_time is None):
                first_tp_time = t
        except Exception:
            continue
    result["seconds_to_first_third_party"] = round((first_tp_time - first_request_time).total_seconds(), 2) if first_request_time and first_tp_time else None

    result["redirect_count"] = sum(1 for r in rows if r.get("status_code", "") in ("301", "302", "303", "307", "308"))

    js_third_party = [
        r for r in rows
        if simplify_ct(r.get("content_type", "")) == "javascript"
        and r.get("category", "") not in ("first_party", "browser_noise", "")
        and r.get("host", "") not in BROWSER_NOISE_DOMAINS
    ]
    result["third_party_js_count"] = len(js_third_party)
    result["third_party_js_domains"] = list({r.get("host", "") for r in js_third_party})[:10]

    cat_counts = Counter(r.get("category", "unknown") for r in rows)
    result["requests_per_category"] = dict(cat_counts.most_common())

    tp_paths = Counter(
        f"{r.get('host','')}{r.get('path','')[:50]}"
        for r in rows
        if r.get("category", "") not in ("first_party", "browser_noise", "")
        and r.get("host", "") not in BROWSER_NOISE_DOMAINS
    )
    result["unique_third_party_endpoints"] = len(tp_paths)

    return result


def find_persistent_trackers(deep: dict) -> dict:
    persistent = {}
    for provider in PROVIDERS:
        domain_phase_map = defaultdict(set)
        for phase in PHASES:
            rows = deep.get(provider, {}).get(phase)
            if not rows:
                continue
            for domain, _ in rows.get("top_third_party_domains_by_count", []):
                domain_phase_map[domain].add(phase)
        persistent[provider] = {
            domain: sorted(phases)
            for domain, phases in domain_phase_map.items()
            if len(phases) >= 2
        }
    return persistent


def load_csv(provider: str, phase: str):
    folder = os.path.join("output", provider, phase)
    if not os.path.exists(folder):
        return None
    for fname in sorted(os.listdir(folder), reverse=True):
        if fname.startswith("classified_capture") and fname.endswith(".csv"):
            path = os.path.join(folder, fname)
            rows = []
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        rows.append(row)
                return rows
            except Exception:
                return None
    for fname in sorted(os.listdir(folder), reverse=True):
        if fname.startswith("capture_") and fname.endswith(".csv"):
            path = os.path.join(folder, fname)
            rows = []
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        rows.append(row)
                return rows
            except Exception:
                return None
    return None


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
        d = json.load(f)
    return d.get("verdict")


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
    deep: dict[str, dict] = {}
    plaintext: dict[str, dict] = {}

    for provider in PROVIDERS:
        data[provider] = {}
        verdicts[provider] = {}
        deep[provider] = {}
        plaintext[provider] = {}
        for phase in PHASES:
            analysis = load_analysis(provider, phase)
            if analysis is not None:
                if "email_leak_count" not in analysis:
                    analysis["email_leak_count"] = 0
                if "email_leaks" not in analysis:
                    analysis["email_leaks"] = []
                if "browser_noise_requests_filtered" not in analysis:
                    analysis["browser_noise_requests_filtered"] = 0
                analysis["by_category_per_domain"] = build_category_per_domain(analysis)
            data[provider][phase] = analysis
            verdicts[provider][phase] = load_encryption(provider, phase)

            rows = load_csv(provider, phase)
            if rows:
                deep[provider][phase] = deep_analyze_csv(rows, provider)
                plaintext[provider][phase] = scan_plaintext(rows, provider)
                hits = len(plaintext[provider][phase])
                print(f"  {provider}/{phase} — {len(rows)} rows, {hits} plaintext hit(s)")
            else:
                deep[provider][phase] = {}
                plaintext[provider][phase] = []

    persistent = find_persistent_trackers(deep)

    template = Template(HTML_TEMPLATE)
    html = template.render(
        providers=PROVIDERS,
        phases=PHASES,
        data=data,
        deep=deep,
        plaintext=plaintext,
        verdicts=verdicts,
        persistent=persistent,
        tracker_results=TRACKER_TEST_RESULTS,
        phase_descriptions=PHASE_DESCRIPTIONS,
        policy=POLICY_DATA,
        generated_at=datetime.now().strftime("%B %d, %Y at %I:%M %p"),
    )

    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", "final_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nReport written to {out_path}")


if __name__ == "__main__":
    main()