import { createPortal } from "react-dom";
import { Button } from "../../ui";
import { IOC_SOURCES_ALL } from "../../data/fixtures";
import { useShell } from "../../lib/shell-context";
import { ToolLanding, NextStepNote } from "./ToolLanding";
import {
  LookupPanel,
  InvestigationsPanel,
  BatchPanel,
  HistoryPanel,
} from "./IocPanels";



export function IocPage(_: { navigate: (to: string) => void }) {
  const { mainTab, setMainTab, subTab, setSubTab, actionsSlot } = useShell();

  // The source count is the only thing this tool contributes to the header's
  // right rail. It is a 32px button like every other control in that rail, not
  // a 22px chip: a chip beside a 32px theme toggle and 32px section chips is a
  // rail of three different heights.
  const headerAction = actionsSlot
    ? createPortal(
        <Button variant="secondary" size="sm" icon="server">
          {IOC_SOURCES_ALL.length} sources
        </Button>,
        actionsSlot,
      )
    : null;

  // The overview is its own main tab and ignores the chip row; the working
  // surface renders whichever chip is selected.
  return (
    <div className="sc-anim-in">
      {headerAction}

      <div className="max-w-[1400px] mx-auto px-5 py-6">
        {mainTab === "overview" ? (
          <ToolLanding
            toolId="ioc"
            copy={{
              eyebrow: "Threat Intelligence Platform",
              headline: ["Dissect. Enrich.", "Defend."],
              subtext:
                "Query 20+ threat-intel sources in a single pass — then enrich, correlate, and export the full picture of any IOC.",
              primaryCta: "Start Lookup",
              onPrimary: () => {
                setSubTab("lookup");
                setMainTab("lookup");
              },
              secondaryCta: "Past Lookups",
              onSecondary: () => {
                setSubTab("history");
                setMainTab("lookup");
              },
              terminal: {
                file: "lookup_result.json",
                body: "json",
                live: true,
                status: "2.4s · 6 engines · 812 YARA rules",
                json: [
                  "{",
                  '  "input": "8.8.8.8",',
                  '  "verdict": "clean",',
                  '  "score": 0.05,',
                  '  "sources": [',
                  '    "greynoise",',
                  '    "abuse_ipdb",',
                  '    "team_cymru"',
                  "  ],",
                  '  "enrichment": { "geoip": "US", "asn": "AS15169" }',
                  "}",
                ],
              },
              stats: [
                { value: "20+", label: "Threat Intel Sources" },
                { value: "10", label: "IOC Types" },
                { value: "812+", label: "YARA Rules" },
                { value: "3", label: "Verdict Tiers" },
                { value: "100", label: "Batch IOCs" },
              ],
              sectionEyebrow: "Capabilities",
              sectionTitle: "Built for the analyst's workflow",
              sectionBody:
                "From a single IOC to a full investigation — all in one platform. Consensus is only returned once every source has answered, and a source with no answer is counted as no answer rather than quietly dropped.",
              features: [
                {
                  title: "Fan-out enrichment",
                  body: "One query goes to every configured provider in parallel and waits for all of them. A verdict drawn from the first four to respond is a different verdict every time, so the wait is the feature.",
                  tags: ["parallel", "33 sources", "consensus"],
                  tagTone: "info",
                },
                {
                  title: "Twelve indicator types",
                  body: "Addresses, CIDRs, domains, URLs, mailboxes, MD5, SHA-1, SHA-256, SSDeep, CVE identifiers and both Bitcoin and Ethereum addresses. The type is detected from the shape of the value.",
                  tags: ["ipv4", "ipv6", "domain", "url", "sha256", "cve"],
                  tagTone: "neutral",
                },
                {
                  title: "Investigations",
                  body: "Group indicators into a case so a verdict can be argued with evidence attached, rather than asserted from a single lookup and forgotten.",
                  tags: ["cases", "evidence", "timeline"],
                  tagTone: "ok",
                },
                {
                  title: "Batch analysis",
                  body: "Up to a hundred indicators in one pass, queued with per-item state so a long run can be watched and a failed item retried without restarting the batch.",
                  tags: ["queue", "100 iocs", "retry"],
                  tagTone: "neutral",
                },
                {
                  title: "Related indicators",
                  body: "Addresses, domains and hashes linked by shared certificates, adjacent subnets, beacon Host headers and hash extraction, each with the relation named.",
                  tags: ["certs", "subnet", "beacon"],
                  tagTone: "info",
                },
                {
                  title: "Five export formats",
                  body: "STIX 2.1, MISP, generic SIEM, CSV and the raw provider payloads, so a result lands in whatever pipeline already exists rather than needing a new one.",
                  tags: ["stix", "misp", "siem", "csv"],
                  tagTone: "ok",
                },
              ],
              workflow: {
                eyebrow: "Workflow",
                title: "From one indicator to a filed case",
                layout: "timeline",
                steps: [
                  { num: "01", title: "Submit", body: "Paste an address, domain, URL, hash, mailbox, CVE or wallet address. The type is detected from its shape." },
                  { num: "02", title: "Enrich", body: "Every configured provider is queried in parallel and the lookup waits for all of them before returning a verdict." },
                  { num: "03", title: "Investigate", body: "Read the consensus, the per-source detail and the related indicators, then group what matters into a case." },
                  { num: "04", title: "Export", body: "Send the result to your SIEM or case manager as STIX 2.1, MISP, generic SIEM or CSV." },
                ],
              },
              after: (
                <div className="mt-14">
                  <NextStepNote
                    toolId="ioc"
                    links={[
                      { to: "malware", text: "any file hash, straight into static analysis" },
                      { to: "events", text: "any address, searched across ingested EVTX" },
                    ]}
                  />
                </div>
              ),
            }}
          />
        ) : (
          <>
            {subTab === "lookup" && <LookupPanel />}
            {subTab === "batch" && <BatchPanel />}
            {subTab === "history" && <HistoryPanel />}
            {subTab === "investigations" && <InvestigationsPanel />}
          </>
        )}
      </div>
    </div>
  );
}
