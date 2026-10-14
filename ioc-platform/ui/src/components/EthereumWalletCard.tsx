import { useState } from "react";
import type {
  EthChainHolding,
  EthCounterparty,
  EthParty,
  EthTransaction,
  EthTxRef,
  EthereumContext,
} from "../services/api";

// Keep in sync with RISK_LABEL_PATTERN in app/backend/etherscan_page.py.
const RISK_PATTERN =
  /phish|hack|exploit|heist|scam|fraud|drainer|sanction|ofac|blocked|lazarus|ransom|mixer|tornado|stolen|laundering|malicious|attacker/i;

const ETHERSCAN = "https://etherscan.io";

function usd(value: number | null | undefined, lowerBound = false): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const digits = Math.abs(value) >= 100 ? 0 : 2;
  const text = value.toLocaleString(undefined, {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
  return lowerBound ? `>${text}` : text;
}

function num(value: number | null | undefined, maxDigits = 6): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return value.toLocaleString(undefined, { maximumFractionDigits: maxDigits });
}

function shortAddr(address?: string | null): string {
  if (!address) return "—";
  return address.length > 14 ? `${address.slice(0, 8)}…${address.slice(-6)}` : address;
}

function txTime(tx: EthTransaction): string {
  if (tx.time) return new Date(tx.time * 1000).toISOString().replace("T", " ").slice(0, 16);
  return tx.datetime_utc ?? "pending";
}

function ExternalLink({ href, children, className = "" }: { href: string; children: React.ReactNode; className?: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={`hover:underline ${className}`}>
      {children}
    </a>
  );
}

function Stat({ label, value, detail, accent = "text-text-primary" }: { label: string; value: string; detail?: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3 min-w-0">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 truncate text-sm font-bold font-mono ${accent}`} title={value}>{value}</div>
      {detail && <div className="mt-0.5 truncate text-xs text-text-secondary" title={detail}>{detail}</div>}
    </div>
  );
}

function PartyLink({ party, self, onPivot }: { party?: EthParty; self: string; onPivot?: (value: string) => void }) {
  const address = party?.address;
  if (!address) return <span className="text-text-secondary">—</span>;
  const isSelf = address.toLowerCase() === self.toLowerCase();
  const risky = Boolean(party?.label && RISK_PATTERN.test(party.label));
  const text = party?.label || shortAddr(address);
  if (isSelf) return <span className="text-text-secondary" title={address}>This address</span>;
  return (
    <button
      type="button"
      onClick={() => onPivot?.(address)}
      title={`${party?.label ? `${party.label} · ` : ""}${address}\nClick to investigate`}
      className={`max-w-full truncate text-left hover:underline ${risky ? "text-red-400 font-semibold" : party?.label ? "text-sky-300" : "text-slate-300"}`}
    >
      {text}
    </button>
  );
}

function Provenance({ title, party, tx, onPivot, self }: { title: string; party?: EthParty; tx?: EthTxRef; onPivot?: (value: string) => void; self: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-bg-elevated/30 p-3 text-xs min-w-0">
      <div className="text-xs uppercase tracking-wider text-text-secondary">{title}</div>
      <div className="mt-1 font-mono truncate">
        {party ? <PartyLink party={party} self={self} onPivot={onPivot} /> : null}
      </div>
      {tx?.tx_hash && (
        <ExternalLink href={`${ETHERSCAN}/tx/${tx.tx_hash}`} className="mt-0.5 block text-xs text-text-secondary">
          {tx.age || "view transaction"} ↗
        </ExternalLink>
      )}
    </div>
  );
}

function ChainBars({ chains }: { chains: EthChainHolding[] }) {
  const max = Math.max(...chains.map((c) => c.value_usd), 1);
  return (
    <div className="space-y-1.5">
      {chains.slice(0, 10).map((chain) => (
        <div key={chain.chain_id || chain.chain} className="text-xs">
          <div className="flex justify-between gap-2">
            <span className="truncate text-text-primary">
              {chain.chain}
              {chain.native_balance != null ? (
                <span className="text-text-secondary"> · {num(chain.native_balance, 4)} {chain.native_symbol}</span>
              ) : chain.token_count ? (
                <span className="text-text-secondary"> · {chain.token_count} tokens</span>
              ) : null}
            </span>
            <span className="shrink-0 font-mono text-text-secondary">
              {usd(chain.value_usd)}{" "}
              {chain.share_pct != null && `(${chain.share_below_pct ? "<" : ""}${chain.share_pct}%)`}
            </span>
          </div>
          <div className="mt-0.5 h-1.5 rounded-full bg-bg-elevated">
            <div className="h-1.5 rounded-full bg-indigo-400/70" style={{ width: `${Math.max(2, (chain.value_usd / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Section({ title, meta, children }: { title: string; meta?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border/60 bg-bg-elevated/20 p-3 min-w-0">
      <div className="mb-2 flex items-center justify-between gap-2 border-b border-border/40 pb-1.5">
        <span className="text-xs font-bold uppercase tracking-wider text-text-primary">{title}</span>
        {meta && <span className="text-xs text-text-secondary">{meta}</span>}
      </div>
      {children}
    </div>
  );
}

export default function EthereumWalletCard({
  wallet,
  onPivot,
}: {
  wallet: EthereumContext;
  onPivot?: (value: string) => void;
}) {
  const [showAllTokens, setShowAllTokens] = useState(false);
  const self = wallet.address;
  const labels = wallet.labels ?? [];
  const riskLabels = wallet.risk_labels ?? [];
  const warnings = wallet.warnings ?? [];
  const tokens = wallet.tokens ?? [];
  const chains = wallet.chains ?? [];
  const transactions = wallet.recent_transactions ?? [];
  const risky: EthCounterparty[] = wallet.risky_counterparties ?? [];
  const tagged: EthCounterparty[] = wallet.tagged_counterparties ?? [];
  const flagged = riskLabels.length > 0 || warnings.length > 0;
  const nativeOnly = wallet.multichain_source === "etherscan_v2_native";
  const visibleTokens = showAllTokens ? tokens : tokens.slice(0, 8);
  const txTotal =
    wallet.transaction_count != null
      ? `${num(wallet.transaction_count, 0)}${wallet.transaction_count_is_lower_bound ? "+" : ""}`
      : "—";

  return (
    <section
      className={`rounded-xl border bg-bg-card p-4 space-y-4 ${flagged ? "border-red-500/50" : "border-border"}`}
      aria-label="Ethereum wallet intelligence"
    >
      {/* Header: identity */}
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border/60 pb-3">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 text-xs font-bold uppercase tracking-wider text-indigo-300 border border-indigo-500/30">
              ETH
            </span>
            <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">Ethereum Wallet Intelligence</h4>
            <span className="rounded-full border border-border/70 px-2 py-0.5 text-xs text-text-secondary">
              {wallet.account_type === "contract" ? "Smart contract" : "Externally owned account"}
            </span>
          </div>
          {(wallet.public_name_tag || wallet.ens_name) && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {wallet.public_name_tag && (
                <span className={`font-semibold ${RISK_PATTERN.test(wallet.public_name_tag) ? "text-red-400" : "text-text-primary"}`}>
                  {wallet.public_name_tag}
                </span>
              )}
              {wallet.ens_name && <span className="font-mono text-sky-300">{wallet.ens_name}</span>}
              {wallet.website && (
                <ExternalLink href={wallet.website} className="text-xs text-text-secondary">{wallet.website} ↗</ExternalLink>
              )}
            </div>
          )}
          <div className="font-mono text-xs text-text-secondary break-all">{self}</div>
        </div>
        <div className="text-right text-xs text-text-secondary space-y-0.5">
          <ExternalLink href={wallet.source_link || `${ETHERSCAN}/address/${self}`} className="text-accent">
            Open in Etherscan ↗
          </ExternalLink>
          {wallet.data_sources && wallet.data_sources.length > 0 && (
            <div>via {wallet.data_sources.map((s) => (s === "etherscan_page" ? "address page" : "V2 API")).join(" + ")}</div>
          )}
        </div>
      </div>

      {/* Holdings, labels and the multichain portfolio come only from the
          Etherscan address page; say so instead of rendering empty tiles. */}
      {!wallet.data_sources?.includes("etherscan_page") && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
          Token holdings, labels and multichain portfolio are unavailable: the Etherscan address page was not
          fetched for this result (older saved result, page blocked, or ETHERSCAN_PAGE_ENRICHMENT=false).
          Re-run the lookup with a live re-scan to load them.
        </div>
      )}

      {/* Threat banner */}
      {flagged && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 space-y-1.5">
          <div className="text-xs font-bold uppercase tracking-wider text-red-300">Flagged by Etherscan</div>
          {warnings.map((warning) => (
            <p key={warning} className="text-xs text-red-200">{warning}</p>
          ))}
          {riskLabels.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {riskLabels.map((label) => (
                <span key={label} className="rounded-full border border-red-500/50 bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-300">
                  {label}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Labels */}
      {labels.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs uppercase tracking-wider text-text-secondary mr-1">Labels</span>
          {labels.map((label) => {
            const isRisk = RISK_PATTERN.test(label.name);
            const chip = (
              <span
                className={`rounded-full border px-2 py-0.5 text-xs ${
                  isRisk ? "border-red-500/50 bg-red-500/10 text-red-300" : "border-border/70 bg-bg-elevated text-text-secondary"
                }`}
                title={label.description}
              >
                {label.name}
              </span>
            );
            return label.slug ? (
              <ExternalLink key={label.name} href={`${ETHERSCAN}/accounts/label/${label.slug}`}>{chip}</ExternalLink>
            ) : (
              <span key={label.name}>{chip}</span>
            );
          })}
        </div>
      )}

      {/* Metrics */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
        <Stat
          label="ETH Balance"
          value={`${num(wallet.balance_eth)} ETH`}
          detail={wallet.balance_usd != null ? usd(wallet.balance_usd) : undefined}
        />
        <Stat label="ETH Price" value={usd(wallet.eth_price_usd)} detail="at lookup time" />
        <Stat
          label="Token Holdings"
          value={usd(wallet.token_holdings_usd, wallet.token_holdings_is_lower_bound)}
          detail={wallet.token_count != null ? `${num(wallet.token_count, 0)} tokens` : undefined}
        />
        <Stat
          label={nativeOnly ? "Multichain (native)" : "Multichain Portfolio"}
          value={usd(wallet.multichain_portfolio_usd)}
          detail={[
            wallet.active_chain_count ? `${wallet.active_chain_count} chains` : "",
            wallet.net_worth_eth != null ? `${num(wallet.net_worth_eth, 4)} ETH` : "",
          ].filter(Boolean).join(" · ") || undefined}
          accent="text-emerald-400"
        />
        <Stat
          label="Total Transactions"
          value={txTotal}
          detail={wallet.pending_transactions ? `${wallet.pending_transactions} pending` : undefined}
        />
        <Stat
          label="Counterparties"
          value={wallet.unique_counterparties != null ? String(wallet.unique_counterparties) : "—"}
          detail={risky.length ? `${risky.length} flagged` : tagged.length ? `${tagged.length} tagged` : "in recent txns"}
          accent={risky.length ? "text-red-400" : "text-text-primary"}
        />
      </div>

      {/* Provenance */}
      {(wallet.funded_by || wallet.first_tx_sent || wallet.latest_tx_sent || wallet.contract_creator || wallet.token_tracker) && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {wallet.funded_by && <Provenance title="Funded by" party={wallet.funded_by} tx={wallet.funded_by} onPivot={onPivot} self={self} />}
          {wallet.contract_creator && <Provenance title="Contract creator" party={wallet.contract_creator} tx={wallet.contract_creator} onPivot={onPivot} self={self} />}
          {wallet.first_tx_sent && <Provenance title="First txn sent" tx={wallet.first_tx_sent} self={self} />}
          {wallet.latest_tx_sent && <Provenance title="Latest txn sent" tx={wallet.latest_tx_sent} self={self} />}
          {wallet.token_tracker && (
            <div className="rounded-lg border border-border/60 bg-bg-elevated/30 p-3 text-xs min-w-0">
              <div className="text-xs uppercase tracking-wider text-text-secondary">Token tracker</div>
              <div className="mt-1 truncate text-text-primary">{wallet.token_tracker}</div>
            </div>
          )}
        </div>
      )}

      {/* Holdings + chain distribution */}
      {(tokens.length > 0 || chains.length > 0) && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {tokens.length > 0 && (
            <Section
              title="Token Holdings"
              meta={`top ${tokens.length} by value${wallet.token_list_size ? ` of ${wallet.token_list_size}` : ""}`}
            >
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="text-left text-xs uppercase text-text-secondary">
                    <th className="pb-1 font-normal">Token</th>
                    <th className="pb-1 font-normal text-right">Amount</th>
                    <th className="pb-1 font-normal text-right">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleTokens.map((token, index) => (
                    <tr key={`${token.contract ?? token.name}-${index}`} className="border-t border-border/30">
                      <td className="py-1 pr-2 max-w-[10rem] truncate">
                        {token.contract ? (
                          <ExternalLink href={`${ETHERSCAN}/token/${token.contract}?a=${self}`} className="text-text-primary">
                            {token.symbol || token.name}
                          </ExternalLink>
                        ) : (
                          token.symbol || token.name
                        )}
                        <span className="ml-1 text-text-secondary">{token.symbol ? token.name : ""}</span>
                      </td>
                      <td className="py-1 text-right text-text-secondary">{num(token.amount, 4)}</td>
                      <td className="py-1 text-right text-text-primary">{usd(token.value_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {tokens.length > 8 && (
                <button
                  type="button"
                  onClick={() => setShowAllTokens((v) => !v)}
                  className="mt-2 text-xs text-accent hover:underline"
                >
                  {showAllTokens ? "Show fewer" : `Show all ${tokens.length}`}
                </button>
              )}
            </Section>
          )}
          {chains.length > 0 && (
            <Section
              title="Multichain Distribution"
              meta={
                nativeOnly
                  ? `native coin balances · ${wallet.multichain_chains_checked ?? chains.length} chains checked`
                  : wallet.multichain_address_count
                    ? `${wallet.multichain_address_count} linked addresses via Blockscan`
                    : undefined
              }
            >
              <ChainBars chains={chains} />
              {nativeOnly && (
                <p className="mt-2 text-xs text-text-secondary">
                  Etherscan did not include its multichain portfolio for this address, so these are native-coin balances from
                  the Etherscan V2 API. Tokens held on other chains
                  {wallet.multichain_chains_unsupported?.length
                    ? ` and ${wallet.multichain_chains_unsupported.join(", ")}`
                    : ""}{" "}
                  are not included (paid Etherscan plan).
                </p>
              )}
            </Section>
          )}
        </div>
      )}

      {/* Flagged counterparties */}
      {risky.length > 0 && (
        <Section title="Flagged Counterparties" meta="threat-related tags in recent transactions">
          <div className="flex flex-wrap gap-1.5">
            {risky.map((party) => (
              <button
                key={party.address}
                type="button"
                onClick={() => onPivot?.(party.address)}
                title={`${party.address}\nClick to investigate`}
                className="rounded-md border border-red-500/40 bg-red-500/10 px-2 py-1 text-xs font-mono text-red-300 hover:bg-red-500/20"
              >
                {party.label} <span className="text-red-400/70">×{party.tx_count}</span>
              </button>
            ))}
          </div>
        </Section>
      )}

      {/* Recent transactions */}
      {transactions.length > 0 && (
        <Section title="Recent Transactions" meta={`latest ${transactions.length} of ${txTotal}`}>
          <div className="max-h-80 overflow-auto">
            <table className="w-full min-w-[640px] text-xs font-mono">
              <thead className="sticky top-0 bg-bg-card">
                <tr className="text-left text-xs uppercase text-text-secondary">
                  <th className="pb-1 font-normal">Time (UTC)</th>
                  <th className="pb-1 font-normal">Dir</th>
                  <th className="pb-1 font-normal">Method</th>
                  <th className="pb-1 font-normal">Counterparty</th>
                  <th className="pb-1 font-normal text-right">Value</th>
                  <th className="pb-1 font-normal text-right">Fee</th>
                  <th className="pb-1 font-normal text-right">Txn</th>
                </tr>
              </thead>
              <tbody>
                {transactions.map((tx, index) => {
                  const counterparty = tx.direction === "OUT" ? tx.to : tx.from;
                  const dirClass =
                    tx.direction === "IN"
                      ? "text-emerald-400 border-emerald-500/40"
                      : tx.direction === "OUT"
                        ? "text-amber-400 border-amber-500/40"
                        : "text-text-secondary border-border";
                  return (
                    <tr key={tx.hash ?? index} className={`border-t border-border/30 ${tx.failed ? "opacity-60" : ""}`}>
                      <td className="py-1 pr-2 whitespace-nowrap text-text-secondary">{txTime(tx)}</td>
                      <td className="py-1 pr-2">
                        <span className={`rounded border px-1 text-xs font-bold ${dirClass}`}>{tx.direction ?? "—"}</span>
                      </td>
                      <td className="py-1 pr-2 max-w-[8rem] truncate text-text-primary" title={tx.method ?? undefined}>
                        {tx.method ?? "—"}
                        {tx.failed && <span className="ml-1 text-red-400">failed</span>}
                      </td>
                      <td className="py-1 pr-2 max-w-[12rem]">
                        <PartyLink party={counterparty} self={self} onPivot={onPivot} />
                      </td>
                      <td className="py-1 pr-2 text-right whitespace-nowrap text-text-primary">
                        {num(tx.value_eth)} ETH
                        {tx.value_usd ? <span className="block text-xs text-text-secondary">{usd(tx.value_usd)}</span> : null}
                      </td>
                      <td className="py-1 pr-2 text-right text-text-secondary">{tx.fee_eth != null ? num(tx.fee_eth, 6) : "—"}</td>
                      <td className="py-1 text-right">
                        {tx.hash ? (
                          <ExternalLink href={`${ETHERSCAN}/tx/${tx.hash}`} className="text-accent">
                            {tx.hash.slice(0, 10)}…
                          </ExternalLink>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </section>
  );
}
