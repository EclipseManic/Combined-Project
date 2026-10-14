import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import BitcoinWalletCard from "../BitcoinWalletCard";
import type { CryptoContext } from "../../services/api";
import btcFixture from "../../__fixtures__/btc-address.json";

const WALLET: CryptoContext = {
  address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  hash160: "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
  n_tx: 66624,
  total_received_btc: 107.4867102,
  total_sent_btc: 0,
  final_balance_btc: 107.4867102,
  recent_transactions: [
    { hash: "23a7da969d343379593be3f571a8be0043c818fc686cb8b708bdfc28c9a6e7f5", time: 1790239438, result_btc: 6.05e-6 },
    { hash: "72e3157ffd71047b4b3ad53c7e5569deebdb3a9311299bbe0e9716dcc96183ad", time: 1789891563, result_btc: -2.5 },
  ],
};

describe("BitcoinWalletCard", () => {
  it("leads with the balances and transaction count", () => {
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText("Final balance")).toBeTruthy();
    // Appears in both the balance tile and the received tile for this wallet.
    expect(screen.getAllByText(/107\.4867/).length).toBeGreaterThan(0);
    expect(screen.getByText("Total received")).toBeTruthy();
    expect(screen.getByText("Total sent")).toBeTruthy();
    expect(screen.getByText("66,624")).toBeTruthy();
  });

  it("derives retention, mean transfer, dormancy and span", () => {
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText("Retention")).toBeTruthy();
    // 107.4867 / 107.4867 = 100% retained: nothing has been swept.
    expect(screen.getByText("100.0%")).toBeTruthy();
    expect(screen.getByText("Mean transfer")).toBeTruthy();
    expect(screen.getByText("Last activity")).toBeTruthy();
    expect(screen.getByText("Observed span")).toBeTruthy();
  });

  it("flags a swept wallet, which is a different risk picture", () => {
    render(<BitcoinWalletCard context={{ ...WALLET, final_balance_btc: 0.2, total_sent_btc: 107.2 }} />);
    expect(screen.getByText(/wallet appears swept/)).toBeTruthy();
    expect(screen.getByText("0.2%")).toBeTruthy();
  });

  it("notes when nothing has been sent on record", () => {
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText("nothing sent on record")).toBeTruthy();
  });

  it("renders recent transactions with direction and explorer links", () => {
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText("Recent transactions")).toBeTruthy();
    expect(screen.getByText("In")).toBeTruthy();
    expect(screen.getByText("Out")).toBeTruthy();
    expect(screen.getByRole("link", { name: /23a7da969d/ })).toBeTruthy();
  });

  it("identifies the address format and links to explorers", () => {
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText(/P2PKH \(legacy\)/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /mempool\.space/ }).getAttribute("href")).toContain(
      "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    );
  });

  it("recognises a bech32 address", () => {
    render(<BitcoinWalletCard context={{ ...WALLET, address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" }} />);
    expect(screen.getByText(/Bech32 \(native SegWit\)/)).toBeTruthy();
  });

  it("pivots into the address on click", () => {
    const onPivot = vi.fn();
    render(<BitcoinWalletCard context={WALLET} onPivot={onPivot} />);
    fireEvent.click(screen.getByTitle(/Click to investigate/));
    expect(onPivot).toHaveBeenCalledWith("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc");
  });

  it("states plainly that no fiat conversion is shown", () => {
    // A hard-coded BTC rate would be wrong within hours, so none is offered.
    render(<BitcoinWalletCard context={WALLET} />);
    expect(screen.getByText(/No fiat conversion is shown/)).toBeTruthy();
  });

  it("degrades cleanly when the wallet has no data", () => {
    render(<BitcoinWalletCard context={{ address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" }} />);
    expect(screen.getByText("Final balance")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(screen.queryByText("Recent transactions")).toBeNull();
  });

  it("renders the real backend payload from the fixture", () => {
    const enrichment = (btcFixture as { enrichment?: { extra?: { bitcoin?: CryptoContext } } }).enrichment;
    const context = enrichment?.extra?.bitcoin;
    expect(context).toBeTruthy();
    const { container } = render(<BitcoinWalletCard context={context as CryptoContext} />);
    const text = container.textContent ?? "";
    expect(text).toMatch(/On-chain wallet activity/);
    expect(text).not.toMatch(/\[object Object\]|undefined|NaN/);
  });
});
