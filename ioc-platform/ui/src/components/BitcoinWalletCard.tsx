import type { CryptoContext } from "../services/api";

/**
 * Bitcoin wallet dashboard.
 *
 * The ETH lookup has a purpose-built wallet card because the backend returns a
 * rich Etherscan page context. BTC had the same treatment available but only got
 * a four-figure stats block, which buried the useful analysis.
 *
 * What the backend actually provides is deliberately small — address, hash160,
 * totals, a transaction count and a list of recent transactions — so the value
 * here is in the *derived* metrics rather than in restating the fields:
 *
 *  - retention: how much of what it ever received it still holds. A wallet that
 *    received 100 BTC and now holds none has been fully swept, which is a very
 *    different risk picture from one that still holds everything.
 *  - mean transfer size: separates an exchange hot wallet (large, few) from a
 *    payment processor or a dust-collection pattern (tiny, many).
 *  - dormancy and wallet span: how long the wallet has been quiet.
 *  - transfer distribution: whether recent activity is concentrated in one
 *    large movement or is many small ones.
 *
 * There is no fiat conversion anywhere: the backend does not fetch a BTC price,
 * and a hard-coded rate would be wrong within hours. Amounts are BTC only.
 */

const BTC_EXPLORERS = [
  { name: "mempool.space", address: (a: string) => `https://mempool.space/address/${a}`, tx: (h: string) => `https://mempool.space/tx/${h}` },
  { name: "Blockchain.info", address: (a: string) => `https://www.blockchain.com/btc/address/${a}`, tx: (h: string) => `https://www.blockchain.com/btc/tx/${h}` },
];

interface RecentTx {
  hash?: string;
  time?: number;
  result_btc?: number;
}

function btc(value: unknown, digits = 4): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return value.toLocaleString(undefined, { maximumFractionDigits: digits });
}

function count(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return value.toLocaleString();
}

function shortHash(hash: string): string {
  return hash.length > 18 ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : hash;
}

function epoch(value: unknown): Date | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return null;
  return new Date(value * 1000);
}

function dayStamp(value: unknown): string {
  const date = epoch(value);
  if (!date) return "—";
  return date.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

function daysSince(value: unknown): number | null {
  const date = epoch(value);
  if (!date) return null;
  return Math.max(0, Math.floor((Date.now() - date.getTime()) / 86_400_000));
}

function ago(days: number): string {
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  if (days < 365) return `${Math.round(days / 30)} months ago`;
  const years = days / 365;
  return `${years.toFixed(1)} years ago`;
}

/** Leading characters identify the address format. */
function addressForm(address: string): string {
  if (address.startsWith("bc1")) return "Bech32 (native SegWit)";
  if (address.startsWith("3")) return "P2SH (script hash)";
  if (address.startsWith("1")) return "P2PKH (legacy)";
  return "Unknown format";
}

function Stat({ label, value, detail, accent = "text-text-primary" }: { label: string; value: string; detail?: string; accent?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 truncate font-mono text-sm font-bold ${accent}`} title={value}>{value}</div>
      {detail && <div className="mt-0.5 truncate text-xs text-text-secondary" title={detail}>{detail}</div>}
    </div>
  );
}

function Derived({ label, value, tone = "neutral", hint }: { label: string; value: string; tone?: "neutral" | "warn" | "good"; hint?: string }) {
  const toneClass = tone === "warn" ? "text-amber-300" : tone === "good" ? "text-emerald-300" : "text-text-primary";
  return (
    <div className="min-w-0 rounded border border-border/60 bg-bg-elevated/30 px-2.5 py-1.5">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`truncate font-mono text-xs font-semibold ${toneClass}`} title={hint ?? value}>{value}</div>
    </div>
  );
}

export default function BitcoinWalletCard({
  context,
  onPivot,
}: {
  context: CryptoContext;
  onPivot?: (value: string, iocType: string) => void;
}) {
  const address = context.address ?? "";
  const received = typeof context.total_received_btc === "number" ? context.total_received_btc : null;
  const sent = typeof context.total_sent_btc === "number" ? context.total_sent_btc : null;
  const balance = typeof context.final_balance_btc === "number" ? context.final_balance_btc : null;
  const nTx = typeof context.n_tx === "number" ? context.n_tx : null;
  const recent: RecentTx[] = Array.isArray(context.recent_transactions) ? (context.recent_transactions as RecentTx[]) : [];

  // Timestamps are the only activity signal available; derive the rest from them.
  const times = recent.map((tx) => tx.time).filter((t): t is number => typeof t === "number" && Number.isFinite(t));
  const newest = times.length ? Math.max(...times) : null;
  const oldest = times.length ? Math.min(...times) : null;
  const dormantDays = daysSince(newest);
  const spanDays = newest !== null && oldest !== null ? Math.floor((newest - oldest) / 86_400_000) : null;

  // Retention: what fraction of everything ever received is still held.
  const retention = received && received > 0 && balance !== null ? (balance / received) * 100 : null;
  const meanTransfer = received !== null && nTx && nTx > 0 ? received / nTx : null;

  // A wallet that sent roughly what it received has been swept.
  const swept = received !== null && balance !== null && received > 0 && balance / received < 0.01;
  const neverSpent = sent !== null && sent === 0 && received !== null && received > 0;

  const amounts = recent.map((tx) => tx.result_btc).filter((v): v is number => typeof v === "number" && Number.isFinite(v));
  const maxAmount = amounts.length ? Math.max(...amounts) : 0;
  const inflow = amounts.filter((v) => v > 0).length;
  const outflow = amounts.filter((v) => v < 0).length;

  return (
    <section className="rounded-xl border border-amber-500/25 bg-bg-card p-4">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border/50 pb-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-xs font-bold uppercase tracking-wider text-amber-400">
              BTC
            </span>
            <h3 className="text-sm font-bold uppercase tracking-wider text-text-primary">On-chain wallet activity</h3>
            <span className="text-xs text-text-secondary">Blockchain.info</span>
          </div>
          <button
            type="button"
            onClick={() => onPivot?.(address, "btc")}
            title={`${address}\nClick to investigate`}
            className="mt-1.5 block max-w-full truncate font-mono text-xs text-sky-300 hover:underline"
          >
            {address}
          </button>
          <div className="mt-0.5 text-xs text-text-secondary">
            {addressForm(address)}
            {context.hash160 ? ` · hash160 ${context.hash160.slice(0, 16)}…` : ""}
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          {BTC_EXPLORERS.map((explorer) => (
            <a
              key={explorer.name}
              href={explorer.address(address)}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded border border-border px-2 py-1 text-xs font-semibold text-text-secondary hover:border-accent/50 hover:text-accent"
            >
              {explorer.name} ↗
            </a>
          ))}
        </div>
      </header>

      {/* Balances */}
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Final balance" value={`${btc(balance, 8)} BTC`} accent="text-amber-300" detail={swept ? "wallet appears swept" : undefined} />
        <Stat label="Total received" value={`${btc(received, 4)} BTC`} />
        <Stat label="Total sent" value={`${btc(sent, 4)} BTC`} detail={neverSpent ? "nothing sent on record" : undefined} />
        <Stat label="Transactions" value={count(nTx)} />
      </div>

      {/* Derived analysis — this is the part a field dump cannot give you. */}
      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Derived
          label="Retention"
          value={retention === null ? "—" : `${retention.toFixed(1)}%`}
          tone={retention !== null && retention < 10 ? "warn" : retention !== null && retention > 95 ? "good" : "neutral"}
          hint="Share of everything ever received that the wallet still holds"
        />
        <Derived
          label="Mean transfer"
          value={meanTransfer === null ? "—" : `${btc(meanTransfer, 6)} BTC`}
          hint="Average value per recorded transaction"
        />
        <Derived
          label="Last activity"
          value={dormantDays === null ? "—" : ago(dormantDays)}
          tone={dormantDays !== null && dormantDays < 30 ? "good" : dormantDays !== null && dormantDays > 730 ? "warn" : "neutral"}
          hint={newest !== null ? dayStamp(newest) : undefined}
        />
        <Derived
          label="Observed span"
          value={spanDays === null ? "—" : `${spanDays.toLocaleString()} d`}
          hint="Between the oldest and newest of the returned transactions"
        />
      </div>

      {recent.length > 0 && (
        <>
          <div className="mt-4 flex flex-wrap items-baseline justify-between gap-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
              Recent transactions <span className="ml-1 font-mono text-text-secondary">{recent.length}</span>
            </h4>
            <span className="text-xs text-text-secondary">
              {inflow} in · {outflow} out of the {recent.length} shown
            </span>
          </div>
          <div className="mt-2 overflow-x-auto">
            <table className="w-full min-w-[34rem] text-xs">
              <thead>
                <tr className="border-b border-border/60 text-left text-xs uppercase tracking-wider text-text-secondary">
                  <th className="py-1 pr-3 font-semibold">Date</th>
                  <th className="py-1 pr-3 font-semibold">Transaction</th>
                  <th className="py-1 pr-3 font-semibold">Direction</th>
                  <th className="py-1 text-right font-semibold">Amount</th>
                </tr>
              </thead>
              <tbody>
                {recent.slice(0, 8).map((tx, index) => {
                  const amount = typeof tx.result_btc === "number" ? tx.result_btc : null;
                  const out = amount !== null && amount < 0;
                  return (
                    <tr key={tx.hash ?? index} className="border-b border-border/30 last:border-0">
                      <td className="py-1 pr-3 font-mono text-text-secondary">{dayStamp(tx.time)}</td>
                      <td className="py-1 pr-3">
                        {tx.hash ? (
                          <a
                            href={BTC_EXPLORERS[0].tx(tx.hash)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-sky-300 hover:underline"
                            title={tx.hash}
                          >
                            {shortHash(tx.hash)}
                          </a>
                        ) : (
                          <span className="text-text-secondary">—</span>
                        )}
                      </td>
                      <td className="py-1 pr-3">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-xs font-semibold uppercase ${
                            out
                              ? "border-rose-500/30 bg-rose-500/10 text-rose-300"
                              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                          }`}
                        >
                          {out ? "Out" : "In"}
                        </span>
                      </td>
                      <td className="py-1 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {/* Relative bar makes an uneven distribution obvious at a glance. */}
                          {maxAmount > 0 && amount !== null && (
                            <span className="h-1.5 w-16 overflow-hidden rounded-full bg-bg-elevated" aria-hidden="true">
                              <span
                                className={`block h-1.5 rounded-full ${out ? "bg-rose-400/70" : "bg-emerald-400/70"}`}
                                style={{ width: `${Math.max(3, (Math.abs(amount) / maxAmount) * 100)}%` }}
                              />
                            </span>
                          )}
                          <span className={`font-mono ${out ? "text-rose-300" : "text-text-primary"}`}>
                            {amount === null ? "—" : `${out ? "−" : "+"}${btc(Math.abs(amount), 8)}`}
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {recent.length > 8 && (
            <p className="mt-1.5 text-xs italic text-text-secondary">
              {recent.length - 8} further transaction{recent.length - 8 === 1 ? "" : "s"} not shown — the full payload is on
              the Enrichment tab.
            </p>
          )}
        </>
      )}

      <p className="mt-3 text-xs text-text-secondary">
        No fiat conversion is shown: the platform does not fetch a BTC price, and a fixed rate would be wrong within
        hours. Balance and flow figures are on-chain BTC and are not third-party estimates.
      </p>
    </section>
  );
}
