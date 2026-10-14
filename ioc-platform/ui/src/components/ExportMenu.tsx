import { useEffect, useRef, useState } from "react";
import { AUTH_REQUIRED_EVENT, apiHeaders, type LookupResponse } from "../services/api";
import { showToast } from "./Toast";

interface Props {
  result: LookupResponse;
}

function requireTaskId(result: LookupResponse): string {
  if (!result.task_id) throw new Error("This snapshot has no server task ID");
  return result.task_id;
}

function ensureExportResponse(response: Response, message: string): Response {
  if (response.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
  }
  if (!response.ok) throw new Error(message);
  return response;
}

export default function ExportMenu({ result }: Props) {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  function downloadJSON() {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.normalized}-ioc-result.json`;
    a.click();
    URL.revokeObjectURL(url);
    setOpen(false);
    showToast("JSON downloaded", "success");
  }

  async function downloadCSV() {
    setExporting("csv");
    try {
      const res = await fetch("/api/export/csv", {
        method: "POST",
        headers: apiHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ioc: result.input, task_id: requireTaskId(result) }),
      });
      ensureExportResponse(res, "CSV export failed");
      const text = await res.text();
      const blob = new Blob([text], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${result.normalized}-ioc-report.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("CSV downloaded", "success");
    } catch (e: any) {
      showToast(e.message, "error");
    }
    setExporting(null);
    setOpen(false);
  }

  async function downloadSTIX() {
    setExporting("stix");
    try {
      const res = await fetch("/api/export/stix", {
        method: "POST",
        headers: apiHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ioc: result.input, task_id: requireTaskId(result) }),
      });
      ensureExportResponse(res, "STIX export failed");
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${result.normalized}-stix-bundle.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("STIX bundle downloaded", "success");
    } catch (e: any) {
      showToast(e.message, "error");
    }
    setExporting(null);
    setOpen(false);
  }

  async function downloadMISP() {
    setExporting("misp");
    try {
      const res = await fetch("/api/export/misp", {
        method: "POST",
        headers: apiHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ioc: result.input, task_id: requireTaskId(result) }),
      });
      ensureExportResponse(res, "MISP export failed");
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${result.normalized}-misp-event.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("MISP event downloaded", "success");
    } catch (e: any) {
      showToast(e.message, "error");
    }
    setExporting(null);
    setOpen(false);
  }

  async function downloadSIEM(fmt: string) {
    const label = { splunk: "Splunk", ecs: "ECS", leef: "LEEF" }[fmt] || fmt;
    setExporting(fmt);
    try {
      const res = await fetch("/api/export/siem", {
        method: "POST",
        headers: apiHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ioc: result.input, task_id: requireTaskId(result), format: fmt }),
      });
      ensureExportResponse(res, `${label} export failed`);
      const text = await res.text();
      const ext = fmt === "ecs" ? "ndjson" : "txt";
      const blob = new Blob([text], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${result.normalized}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      showToast(`${label} export downloaded`, "success");
    } catch (e: any) {
      showToast(e.message, "error");
    }
    setExporting(null);
    setOpen(false);
  }

  function copySummary() {
    navigator.clipboard.writeText(result.executive_summary || "No executive summary available for this IOC.");
    setOpen(false);
    showToast("Summary copied", "success");
  }

  function copyShareLink() {
    const type = result.password_prehashed ? "password_sha1" : result.ioc_type;
    const url = `${window.location.origin}/?page=lookup&ioc=${encodeURIComponent(result.input)}&ioc_type=${encodeURIComponent(type)}`;
    navigator.clipboard.writeText(url);
    setOpen(false);
    showToast("Share link copied", "success");
  }

  return (
    <div className="relative" ref={menuRef}>
      <button
        ref={triggerRef}
        onClick={() => setOpen(!open)}
        disabled={!!exporting}
        aria-haspopup="menu"
        aria-expanded={open}
        className="text-xs px-3 py-1.5 bg-bg-elevated border border-border rounded-md text-text-secondary hover:text-text-primary disabled:opacity-50 transition-colors"
      >
        {exporting ? `Exporting ${exporting}...` : "Export"}
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1 z-20 bg-bg-card border border-border rounded-lg shadow-xl py-1 min-w-[160px]" role="menu" aria-label="Export options">
            <button onClick={downloadJSON} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
              Download JSON
            </button>
            <button onClick={downloadCSV} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
              Download CSV
            </button>
            <button onClick={downloadSTIX} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download STIX
            </button>
            <button onClick={downloadMISP} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download MISP
            </button>
            <div className="border-t border-border my-1" />
            <button onClick={() => downloadSIEM("splunk")} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download Splunk
            </button>
            <button onClick={() => downloadSIEM("ecs")} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download ECS (ELK)
            </button>
            <button onClick={() => downloadSIEM("leef")} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Download LEEF (QRadar)
            </button>
            <div className="border-t border-border my-1" />
            <button onClick={copySummary} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
              Copy Summary
            </button>
            <button onClick={copyShareLink} className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors flex items-center gap-2">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
              Copy Share Link
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export function ExportTab({ result }: Props) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
          <h3 className="text-sm font-semibold">JSON Export</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Full response including all source results, enrichment, and relationships.</p>
        <button onClick={() => {
          const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = `${result.normalized}-ioc-result.json`; a.click();
          URL.revokeObjectURL(url);
        }} className="px-4 py-2 bg-accent text-[#06070d] text-xs rounded-lg hover:bg-accent/90 transition-colors">
          Download JSON
        </button>
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
          <h3 className="text-sm font-semibold">CSV Report</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Flat table of all source results with verdicts and scores.</p>
        <ExportButton label="Download CSV" action="csv" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          <h3 className="text-sm font-semibold">STIX 2.1 Bundle</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Threat intelligence in standard STIX 2.1 format for sharing with other platforms.</p>
        <ExportButton label="Download STIX" action="stix" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          <h3 className="text-sm font-semibold">MISP Event</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">MISP threat sharing format with attributes, objects (geoip, whois), and verdict tags.</p>
        <ExportButton label="Download MISP" action="misp" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          <h3 className="text-sm font-semibold">SIEM — Splunk</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Key=value format for Splunk ingestion with source, verdict, score, and tags.</p>
        <ExportButton label="Download Splunk" action="splunk" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          <h3 className="text-sm font-semibold">SIEM — ECS (ELK)</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Elastic Common Schema NDJSON for Elasticsearch ingestion.</p>
        <ExportButton label="Download ECS" action="ecs" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          <h3 className="text-sm font-semibold">SIEM — LEEF (QRadar)</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">IBM QRadar LEEF format with IOC details and verdict severity.</p>
        <ExportButton label="Download LEEF" action="leef" result={result} />
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
          <h3 className="text-sm font-semibold">Copy & Share</h3>
        </div>
        <p className="text-xs text-text-secondary mb-3">Copy the executive summary or a shareable link to this result.</p>
        <div className="flex gap-2">
          <button onClick={() => { navigator.clipboard.writeText(result.executive_summary || "No executive summary available for this IOC."); showToast("Summary copied", "success"); }}
            className="px-4 py-2 bg-bg-elevated border border-border text-text-secondary text-xs rounded-lg hover:text-text-primary transition-colors">
            Copy Summary
          </button>
          <button onClick={() => { const url = `${window.location.origin}/?page=lookup&ioc=${encodeURIComponent(result.input)}`; navigator.clipboard.writeText(url); showToast("Link copied", "success"); }}
            className="px-4 py-2 bg-bg-elevated border border-border text-text-secondary text-xs rounded-lg hover:text-text-primary transition-colors">
            Copy Link
          </button>
        </div>
      </div>
    </div>
  );
}

type ExportAction = "csv" | "stix" | "misp" | "splunk" | "ecs" | "leef";

const SIEM_ACTIONS: ExportAction[] = ["splunk", "ecs", "leef"];

function ExportButton({ label, action, result }: { label: string; action: ExportAction; result: LookupResponse }) {
  const [loading, setLoading] = useState(false);
  return (
    <button
      onClick={async () => {
        setLoading(true);
        try {
          const isSiem = SIEM_ACTIONS.includes(action);
          const endpoint = isSiem ? "/api/export/siem" : `/api/export/${action}`;
          const body = isSiem
            ? { ioc: result.input, task_id: requireTaskId(result), format: action }
            : { ioc: result.input, task_id: requireTaskId(result) };
          const res = await fetch(endpoint, {
            method: "POST",
            headers: apiHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify(body),
          });
          ensureExportResponse(res, "Export failed");
          const ext = action === "csv" ? "csv" : isSiem ? "txt" : "json";
          const content = action === "csv" ? await res.text() : isSiem ? await res.text() : JSON.stringify(await res.json(), null, 2);
          const mime = action === "csv" ? "text/csv" : "application/json";
          const blob = new Blob([content], { type: mime });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = `${result.normalized}-${action}.${ext}`; a.click();
          URL.revokeObjectURL(url);
          showToast(`${action.toUpperCase()} downloaded`, "success");
        } catch (e: any) {
          showToast(e.message, "error");
        }
        setLoading(false);
      }}
      disabled={loading}
      className="px-4 py-2 bg-accent text-[#06070d] text-xs rounded-lg hover:bg-accent/90 disabled:opacity-50 transition-colors"
    >
      {loading ? "Downloading..." : label}
    </button>
  );
}
