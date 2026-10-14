import type {
  AsnContext,
  MitreAttackContext,
  HostArtifactContext,
  FilenameContext,
  FilePathContext,
  UserAgentContext,
  MacContext,
  HashResultEntry,
  SsdeepContext,
} from "../services/api";

/**
 * Dedicated Investigation-view cards for "context" IOC types whose structured
 * enrichment previously only appeared in the Sources tab. Each card reads the
 * typed `enrichment.extra.*` payload the backend produces and renders it inline
 * so an analyst never has to open raw JSON to see it.
 */

function CardShell({
  title,
  source,
  children,
  accent = "border-border",
}: {
  title: string;
  source: string;
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <section className={`rounded-xl border ${accent} bg-bg-card p-4 space-y-3`}>
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">{title}</h4>
        <span className="text-xs text-text-secondary">{source}</span>
      </div>
      {children}
    </section>
  );
}

function Field({ label, value, mono, tone }: { label: string; value: React.ReactNode; mono?: boolean; tone?: string }) {
  return (
    <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
      <span className="text-xs uppercase tracking-wider text-text-secondary block">{label}</span>
      <span className={`font-semibold mt-0.5 block break-all ${mono ? "font-mono text-xs" : ""} ${tone ?? "text-text-primary"}`}>
        {value ?? "—"}
      </span>
    </div>
  );
}

function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-xs font-bold uppercase tracking-wider border ${
        on
          ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
          : "bg-emerald-500/10 text-emerald-400/80 border-emerald-500/20"
      }`}
    >
      {label}: {on ? "Yes" : "No"}
    </span>
  );
}

export function AsnCard({ asn }: { asn: AsnContext }) {
  const prefixes = Array.isArray(asn.announced_prefixes) ? asn.announced_prefixes : [];
  return (
    <CardShell title="Autonomous System Intelligence" source="RIPEstat">
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Resource" value={asn.resource} mono />
        <Field label="Holder" value={asn.holder || "Unknown"} />
        <Field label="Announced Prefixes" value={asn.announced_prefix_count ?? prefixes.length} />
      </div>
      {prefixes.length > 0 && (
        <div className="space-y-1 pt-1">
          <span className="text-xs uppercase tracking-wider text-text-secondary block">
            Announced Prefixes ({prefixes.length})
          </span>
          <div className="max-h-40 overflow-y-auto flex flex-wrap gap-1 font-mono text-xs">
            {prefixes.slice(0, 60).map((p, i) => (
              <span key={i} className="rounded bg-bg-elevated px-1.5 py-0.5 border border-border/60 text-slate-300">
                {String((p as { prefix?: string })?.prefix ?? "—")}
              </span>
            ))}
          </div>
        </div>
      )}
    </CardShell>
  );
}

export function MitreCard({ mitre }: { mitre: MitreAttackContext }) {
  return (
    <CardShell title="MITRE ATT&CK Context" source="attack.mitre.org">
      <div className="space-y-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="rounded bg-accent/15 px-2 py-0.5 text-xs font-bold font-mono text-accent border border-accent/30">
            {mitre.id}
          </span>
          {mitre.kind && (
            <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-xs uppercase tracking-wider text-text-secondary border border-border/60">
              {mitre.kind}
            </span>
          )}
        </div>
        {mitre.title && <div className="font-semibold text-text-primary">{mitre.title}</div>}
        {mitre.description && (
          <p className="text-xs leading-relaxed text-text-secondary">{mitre.description}</p>
        )}
        {mitre.url && (
          <a
            href={mitre.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs font-semibold text-accent hover:underline"
          >
            View on MITRE ATT&CK
            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
              <polyline points="15 3 21 3 21 9" />
              <line x1="10" y1="14" x2="21" y2="3" />
            </svg>
          </a>
        )}
      </div>
    </CardShell>
  );
}

export function HostArtifactCard({ artifact }: { artifact: HostArtifactContext }) {
  const type = artifact.type || "artifact";
  const fields: [string, React.ReactNode][] = [["Type", type.replace(/_/g, " ")]];
  if (artifact.server) fields.push(["Server", artifact.server]);
  if (artifact.pipe_name) fields.push(["Pipe Name", artifact.pipe_name]);
  if (artifact.hive) fields.push(["Registry Hive", artifact.hive]);
  if (artifact.key_path) fields.push(["Key Path", artifact.key_path]);
  if (artifact.depth != null) fields.push(["Key Depth", artifact.depth]);
  if (artifact.namespace) fields.push(["Namespace", artifact.namespace]);
  if (artifact.name) fields.push(["Name", artifact.name]);

  return (
    <CardShell title="Host Artifact Structure" source="Structural Analysis">
      <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
        <span className="text-xs uppercase tracking-wider text-text-secondary block">Value</span>
        <span className="font-mono text-xs text-text-primary mt-0.5 block break-all">{artifact.value}</span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        {fields.map(([label, value], i) => (
          <Field key={i} label={label} value={value} mono={label !== "Type"} />
        ))}
      </div>
      <p className="text-xs text-text-secondary">
        Threat corpus unavailable locally — structure shown for correlation and pivoting.
      </p>
    </CardShell>
  );
}

export function FilenameCard({ filename }: { filename: FilenameContext }) {
  return (
    <CardShell
      title="Filename Analysis"
      source="Structural Analysis"
      accent={filename.double_extension ? "border-amber-500/40" : "border-border"}
    >
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Filename" value={filename.value} mono />
        <Field label="Extension" value={filename.extension ? `.${filename.extension}` : "none"} mono />
        <Field label="Category" value={filename.category} />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Flag on={Boolean(filename.double_extension)} label="Double extension" />
      </div>
      {filename.double_extension && (
        <p className="text-xs leading-relaxed text-amber-300/90 rounded bg-amber-500/10 border border-amber-500/25 p-2">
          Double-extension masquerade detected — the visible extension differs from the real file type,
          a common social-engineering lure. Correlate the file hash with malware feeds.
        </p>
      )}
    </CardShell>
  );
}

export function FilePathCard({ path }: { path: FilePathContext }) {
  return (
    <CardShell
      title={`${path.os === "windows" ? "Windows" : "Linux"} Path Analysis`}
      source="Structural Analysis"
      accent={path.suspicious_location ? "border-amber-500/40" : "border-border"}
    >
      <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
        <span className="text-xs uppercase tracking-wider text-text-secondary block">Full Path</span>
        <span className="font-mono text-xs text-text-primary mt-0.5 block break-all">{path.value}</span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Directory" value={path.directory} mono />
        <Field label="Filename" value={path.filename} mono />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Flag on={Boolean(path.suspicious_location)} label="Staging location" />
      </div>
      {path.suspicious_location && (
        <p className="text-xs leading-relaxed text-amber-300/90 rounded bg-amber-500/10 border border-amber-500/25 p-2">
          Located in a common malware staging directory
          {path.location_marker ? ` (${path.location_marker})` : ""}; execution from here is frequently
          associated with dropped payloads.
        </p>
      )}
    </CardShell>
  );
}

export function UserAgentCard({ ua }: { ua: UserAgentContext }) {
  return (
    <CardShell
      title="User-Agent Analysis"
      source="Structural Analysis"
      accent={ua.is_automation ? "border-amber-500/40" : "border-border"}
    >
      <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
        <span className="text-xs uppercase tracking-wider text-text-secondary block">User-Agent</span>
        <span className="font-mono text-xs text-text-primary mt-0.5 block break-all">{ua.value}</span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Client" value={ua.client} />
        <Field label="Platform" value={ua.platform || "Unknown"} />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Flag on={Boolean(ua.is_automation)} label="Automation client" />
      </div>
      {ua.is_automation && (
        <p className="text-xs leading-relaxed text-amber-300/90 rounded bg-amber-500/10 border border-amber-500/25 p-2">
          Automation/scripting client — rarely a human browser. Common in scanners, scrapers and C2
          beacons; correlate with the source IP's request pattern.
        </p>
      )}
    </CardShell>
  );
}

export function MacCard({ mac }: { mac: MacContext }) {
  return (
    <CardShell
      title="MAC Address Intelligence"
      source="OUI Lookup"
      accent={mac.virtualization ? "border-sky-500/40" : "border-border"}
    >
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Address" value={mac.value} mono />
        <Field label="OUI" value={mac.oui} mono />
        <Field
          label="Vendor"
          value={mac.vendor}
          tone={mac.virtualization ? "text-sky-300" : "text-text-primary"}
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Flag on={Boolean(mac.virtualization)} label="Virtualization" />
        <Flag on={Boolean(mac.locally_administered)} label="Locally administered" />
        <Flag on={Boolean(mac.multicast)} label="Multicast" />
      </div>
      {mac.virtualization && (
        <p className="text-xs leading-relaxed text-sky-200/90 rounded bg-sky-500/10 border border-sky-500/25 p-2">
          OUI belongs to {mac.vendor} — this endpoint is likely a virtual machine or sandbox rather than
          physical hardware.
        </p>
      )}
    </CardShell>
  );
}

export function HashFileCard({ results }: { results: HashResultEntry[] }) {
  const entry = results[0];
  return (
    <CardShell title="File Hash Intelligence" source="CIRCL hashlookup">
      {entry ? (
        <>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {entry.filename && <Field label="Known Filename" value={entry.filename} />}
            {entry.size != null && entry.size !== "" && <Field label="File Size" value={String(entry.size)} mono />}
            {entry.mime && <Field label="MIME Type" value={entry.mime} mono />}
            {entry.database && <Field label="Reference DB" value={entry.database} />}
            {entry.source && <Field label="Source" value={entry.source} />}
            {entry.trust != null && <Field label="Trust" value={String(entry.trust)} mono />}
          </div>
          <p className="text-xs leading-relaxed text-emerald-300/80 rounded bg-emerald-500/10 border border-emerald-500/25 p-2">
            Present in a known-file reference database. A known file is not automatically benign — weigh
            against the reputation providers above.
          </p>
        </>
      ) : (
        <p className="text-xs leading-relaxed text-text-secondary">
          Not present in the CIRCL known-file corpus. The verdict above is derived from reputation and
          malware providers.
        </p>
      )}
    </CardShell>
  );
}

export function SsdeepCard({ ssdeep }: { ssdeep: SsdeepContext }) {
  return (
    <CardShell title="Fuzzy Hash Structure" source="Structural Analysis">
      <div className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Block Size" value={ssdeep.block_size ?? "—"} mono />
        <Field label="Chunk 1 Length" value={ssdeep.first_chunk_length ?? "—"} mono />
        <Field label="Chunk 2 Length" value={ssdeep.second_chunk_length ?? "—"} mono />
        <Field label="Alphabet Size" value={ssdeep.alphabet ? ssdeep.alphabet.length : "—"} mono />
      </div>
      <p className="text-xs text-text-secondary">
        Fuzzy-match corpus unavailable locally — structure shown for similarity pivoting.
      </p>
    </CardShell>
  );
}

/**
 * Renders whichever context cards apply to the given enrichment.extra payload.
 * Returns null when none apply (so the caller can decide on a placeholder).
 */
export default function ContextIntelCard({ extra }: { extra?: import("../services/api").EnrichmentExtra }) {
  if (!extra) return null;
  // enrich_hash() always returns extra.hash_results, even as an empty array when
  // hashlookup is disabled or the hash is unknown. An empty array is truthy in JS,
  // so gate on length to stay consistent with hasContextIntel() below — otherwise
  // this card and the "no technical intelligence" placeholder would both render.
  const hashResults =
    Array.isArray(extra.hash_results) && extra.hash_results.length > 0 ? extra.hash_results : null;
  return (
    <>
      {extra.asn && <AsnCard asn={extra.asn} />}
      {extra.mitre_attack && <MitreCard mitre={extra.mitre_attack} />}
      {extra.host_artifact && <HostArtifactCard artifact={extra.host_artifact} />}
      {extra.filename && <FilenameCard filename={extra.filename} />}
      {extra.file_path && <FilePathCard path={extra.file_path} />}
      {extra.user_agent && <UserAgentCard ua={extra.user_agent} />}
      {extra.mac && <MacCard mac={extra.mac} />}
      {hashResults && <HashFileCard results={hashResults} />}
      {extra.ssdeep && <SsdeepCard ssdeep={extra.ssdeep} />}
    </>
  );
}

/** True when extra carries at least one context payload this card can render. */
export function hasContextIntel(extra?: import("../services/api").EnrichmentExtra): boolean {
  if (!extra) return false;
  return Boolean(
    extra.asn ||
      extra.mitre_attack ||
      extra.host_artifact ||
      extra.filename ||
      extra.file_path ||
      extra.user_agent ||
      extra.mac ||
      (Array.isArray(extra.hash_results) && extra.hash_results.length > 0) ||
      extra.ssdeep
  );
}
