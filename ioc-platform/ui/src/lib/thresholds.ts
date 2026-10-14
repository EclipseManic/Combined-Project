// Shared scoring thresholds — single source of truth for verdict classification (frontend).
// Backend mirror: app/backend/thresholds.py (keep values in sync).

export const MALICIOUS_HIGH = 0.7;
export const MALICIOUS_MEDIUM = 0.4;
export const SUSPICIOUS = 0.15;

// Display scale (0 - 100) — composite.score as shown in UI/reports
export const DISPLAY_MALICIOUS = MALICIOUS_HIGH * 100; // 70
export const DISPLAY_SUSPICIOUS = MALICIOUS_MEDIUM * 100; // 40
export const DISPLAY_CLEAN = SUSPICIOUS * 100; // 15
