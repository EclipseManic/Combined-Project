"""Shared scoring thresholds — single source of truth for verdict classification.

Backend consumers: scorer.py, executive_summary.py, main.py (HTML report).
Frontend mirror: ui/src/lib/thresholds.ts (keep values in sync).
"""

# Raw score thresholds (composite raw score on 0.0 - 1.0 scale)
MALICIOUS_HIGH = 0.7
MALICIOUS_MEDIUM = 0.4
SUSPICIOUS = 0.15

# Malicious-source count overrides (multi-source agreement)
MALICIOUS_OVERRIDE_COUNT_HIGH = 2
MALICIOUS_OVERRIDE_COUNT_MEDIUM = 1

# Display scale (0 - 100) — composite.score as shown in UI/reports
DISPLAY_MALICIOUS = MALICIOUS_HIGH * 100
DISPLAY_SUSPICIOUS = MALICIOUS_MEDIUM * 100
DISPLAY_CLEAN = SUSPICIOUS * 100

# Executive summary wording thresholds (display scale)
SUMMARY_SIGNIFICANT = DISPLAY_MALICIOUS
SUMMARY_CAUTION = DISPLAY_SUSPICIOUS
SUMMARY_NO_THREAT = DISPLAY_CLEAN

# A malicious source must score >= this to be counted as "flagged malicious" in summary
MALICIOUS_SOURCE_SCORE = MALICIOUS_HIGH

# EPSS high threshold (CVE exploit probability, 0.0 - 1.0)
EPSS_HIGH = 0.5

# Minimum number of contributing sources for "high" confidence on a clean verdict
MIN_SOURCES_HIGH_CONFIDENCE = 2

# A-1: 2-adapter override requires minimum cumulative decayed weight of malicious sources
OVERRIDE_MIN_MALICIOUS_WEIGHT = 1.2
