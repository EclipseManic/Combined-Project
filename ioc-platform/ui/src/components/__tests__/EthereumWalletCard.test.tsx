import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import EthereumWalletCard from "../EthereumWalletCard";
import type { EthereumContext } from "../../services/api";

const SELF = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";
const PHISHER = "0x087238209BaC1D2985b12d7A4bE5bd75daA17243";
const FUNDER = "0x4976A4A02f38326660D17bf34b431dC6e2eb2327";

const wallet: EthereumContext = {
  address: SELF,
  account_type: "address",
  public_name_tag: "Ronin Bridge Exploiter",
  labels: [{ name: "Exploit" }, { name: "OFAC-Sanctioned", slug: "ofac-sanctioned" }, { name: "Gitcoin Grantee" }],
  risk_labels: ["Ronin Bridge Exploiter", "Exploit", "OFAC-Sanctioned"],
  warnings: ["This address is reported to be involved in a hack targeting the Ronin bridge ."],
  balance_eth: 101.8,
  balance_usd: 271933.78,
  eth_price_usd: 2671.19,
  token_holdings_usd: 0.01,
  token_count: 40,
  multichain_portfolio_usd: 271954.63,
  active_chain_count: 8,
  chains: [{ chain: "Ethereum", chain_id: "ETH", token_count: 1, value_usd: 271934, share_pct: 100 }],
  tokens: [{ name: "Akita Inu", symbol: "AKITA", amount: 13300000, value_usd: 0 }],
  funded_by: { address: FUNDER, label: "Binance 20", tx_hash: "0x" + "e".repeat(64), age: "4 yrs ago" },
  transaction_count: 430,
  unique_counterparties: 18,
  risky_counterparties: [{ address: PHISHER, label: "Fake_Phishing5370992", tx_count: 1 }],
  recent_transactions: [
    {
      hash: "0x" + "1".repeat(64),
      method: "Transfer",
      time: 1785147287,
      direction: "IN",
      from: { address: PHISHER, label: "Fake_Phishing5370992" },
      to: { address: SELF, label: "Ronin Bridge Exploiter" },
      value_eth: 0.000011,
      value_usd: 0.03,
    },
  ],
  data_sources: ["etherscan_page"],
};

describe("EthereumWalletCard", () => {
  it("surfaces Etherscan flags, valuation and activity metrics", () => {
    render(<EthereumWalletCard wallet={wallet} />);

    expect(screen.getByText("Flagged by Etherscan")).toBeTruthy();
    expect(screen.getByText(/involved in a hack targeting the Ronin bridge/)).toBeTruthy();
    expect(screen.getAllByText("OFAC-Sanctioned").length).toBeGreaterThan(0);
    expect(screen.getByText("Gitcoin Grantee")).toBeTruthy();
    expect(screen.getByText("101.8 ETH")).toBeTruthy();
    expect(screen.getByText("430")).toBeTruthy();
    expect(screen.getByText("Multichain Distribution")).toBeTruthy();
    expect(screen.getByText("Binance 20")).toBeTruthy();
  });

  it("pivots to counterparties and funders as ETH lookups", () => {
    const onPivot = vi.fn();
    render(<EthereumWalletCard wallet={wallet} onPivot={onPivot} />);

    fireEvent.click(screen.getByText("Binance 20"));
    expect(onPivot).toHaveBeenCalledWith(FUNDER);

    // The flagged counterparty appears in the chip list and the transactions table.
    fireEvent.click(screen.getAllByText(/Fake_Phishing5370992/)[0]);
    expect(onPivot).toHaveBeenCalledWith(PHISHER);
  });

  it("renders a clean wallet without a threat banner", () => {
    render(
      <EthereumWalletCard
        wallet={{ address: SELF, balance_eth: 1, transaction_count: 3, labels: [], risk_labels: [], warnings: [] }}
      />,
    );
    expect(screen.queryByText("Flagged by Etherscan")).toBeNull();
    expect(screen.getByText("1 ETH")).toBeTruthy();
    // No address-page data: explain why holdings are missing.
    expect(screen.getByText(/Token holdings, labels and multichain portfolio are unavailable/)).toBeTruthy();
  });

  it("does not show the missing-holdings notice when the page was fetched", () => {
    render(<EthereumWalletCard wallet={wallet} />);
    expect(screen.queryByText(/multichain portfolio are unavailable/)).toBeNull();
  });
});
