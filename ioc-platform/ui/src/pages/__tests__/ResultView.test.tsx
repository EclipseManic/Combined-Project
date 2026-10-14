import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import btcFixture from "../../__fixtures__/btc-address.json";
import ethFixture from "../../__fixtures__/eth-address.json";
import cveFixture from "../../__fixtures__/cve-2021-44228.json";
import emailFixture from "../../__fixtures__/email-test.json";
import ipFixture from "../../__fixtures__/ip-8.8.8.8.json";
import type { LookupResponse } from "../../services/api";
import ResultView from "../ResultView";

const FIXTURES: [string, unknown][] = [
  ["ip", ipFixture],
  ["cve", cveFixture],
  ["email", emailFixture],
  ["btc", btcFixture],
  ["eth", ethFixture],
];

function renderResult(fixture: unknown, onNewSearch = vi.fn()) {
  return render(<ResultView result={fixture as LookupResponse} onNewSearch={onNewSearch} />);
}

describe("ResultView", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: "Not found" }), { status: 404 }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(FIXTURES)("renders the %s payload without placeholder garbage", (_name, fixture) => {
    const { container } = renderResult(fixture);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/\[object Object\]|undefined|NaN|Invalid Date/);
  });

  it("shows the CVE verdict from final_assessment, not the unknown composite", () => {
    renderResult(cveFixture);
    expect(screen.getByTestId("headline-verdict").textContent).toBe("Critical");
    expect(screen.getByTestId("headline-score").textContent).toBe("CVSS 10.0 · risk 100/100");
    expect(screen.getByTestId("headline-reason").textContent).toMatch(/critical severity \(CVSS 10\)/);
  });

  it("shows a breached email as breached with its exposure score", () => {
    renderResult(emailFixture);
    expect(screen.getByTestId("headline-verdict").textContent).toBe("Breached");
    expect(screen.getByTestId("headline-score").textContent).toBe("77/100");
  });

  it("does not show an unknown BTC verdict as a 0 score", () => {
    renderResult(btcFixture);
    expect(screen.getByTestId("headline-score").textContent).toBe("Not scored");
  });

  it("lists findings first, collapses provider problems and hides not-applicable providers", () => {
    const { container } = renderResult(ipFixture);
    const findings = screen.getByRole("region", { name: "Provider findings" });
    expect(within(findings).getByText("VirusTotal")).toBeTruthy();
    expect(within(findings).queryByText("GreyNoise")).toBeNull();

    const problems = container.querySelector("details[aria-label='Provider problems']") as HTMLDetailsElement;
    expect(problems).toBeTruthy();
    expect(problems.open).toBe(false);
    expect(problems.textContent).toMatch(/GreyNoise/);
    expect(problems.textContent).toMatch(/Rate limited/);

    const text = container.textContent ?? "";
    expect(text).not.toMatch(/AbstractAPI/);
    expect(text).not.toMatch(/Blockchain\.info/);
    // Transport tags are not rendered as chips.
    expect(text).not.toMatch(/votes_malicious/);
  });

  it("re-runs a lookup with cache bypass from the re-scan button", () => {
    const onNewSearch = vi.fn();
    renderResult(ipFixture, onNewSearch);
    fireEvent.click(screen.getAllByRole("button", { name: /re-scan/i })[0]);
    expect(onNewSearch).toHaveBeenCalledWith("8.8.8.8", "ipv4", true);
  });

  it("shows no enrichment module on the Investigation tab", () => {
    // Investigation is the verdict and provider evidence only. Every enrichment
    // card used to be mounted here as well as on the Enrichment tab, so the
    // same data appeared twice.
    const { container } = renderResult(ipFixture);
    const panel = container.querySelector("#result-panel") as HTMLElement;
    const text = panel.textContent ?? "";

    expect(screen.getByRole("region", { name: "Provider findings" })).toBeTruthy();
    for (const marker of [
      /Network & Routing Context/,
      /Host Attack Surface/i,
      /Abuse Reports/i,
      /Enrichment & OSINT Data/,
      /Collection status/,
    ]) {
      expect(text).not.toMatch(marker);
    }
  });

  it("moves every enrichment module onto the Enrichment tab", () => {
    const { container } = renderResult(ipFixture);
    fireEvent.click(screen.getByRole("tab", { name: /Enrichment/i }));
    const panel = container.querySelector("#result-panel") as HTMLElement;
    const text = panel.textContent ?? "";

    // The IP lookup that used to render geo + host vulns on Investigation.
    expect(text).toMatch(/Enrichment & OSINT Data/);
    expect(text).toMatch(/Collection status/);
    expect(screen.queryByRole("region", { name: "Provider findings" })).toBeNull();
  });

  it("lays provider findings out in a multi-column grid", () => {
    const { container } = renderResult(ipFixture);
    const findings = screen.getByRole("region", { name: "Provider findings" });
    const grid = findings.querySelector(".grid") as HTMLElement;
    expect(grid.className).toMatch(/md:grid-cols-2/);
    expect(grid.className).toMatch(/2xl:grid-cols-3/);
    expect(container.querySelector("#result-panel")).toBeTruthy();
  });

  it("puts the Bitcoin dashboard on the Investigation tab", () => {
    const { container } = renderResult(btcFixture);
    const panel = container.querySelector("#result-panel") as HTMLElement;
    expect(panel.textContent).toMatch(/On-chain wallet activity/);
    expect(screen.getByRole("region", { name: "Provider findings" })).toBeTruthy();
  });

  it("puts the Ethereum dashboard on the Investigation tab too", () => {
    // Consistency: BTC and ETH are the same kind of indicator and get the same
    // treatment. Leaving the ETH card on Enrichment only was an oversight from
    // the tab split.
    const { container } = renderResult(ethFixture);
    const panel = container.querySelector("#result-panel") as HTMLElement;
    expect(panel.textContent).not.toMatch(/Enrichment & OSINT Data/);
    expect(panel.textContent).toMatch(/0x742d35Cc6634C0532925a3b844Bc454e4438f44e/);
    expect(screen.getByRole("region", { name: "Provider findings" })).toBeTruthy();
  });

  it("does not repeat the wallet dashboards on the Enrichment tab", () => {
    const { container } = renderResult(btcFixture);
    fireEvent.click(screen.getByRole("tab", { name: /Enrichment/i }));
    const panel = container.querySelector("#result-panel") as HTMLElement;
    // The dashboard belongs to Investigation; Enrichment carries the depth.
    expect(panel.textContent).not.toMatch(/On-chain wallet activity/);
    expect(panel.textContent).toMatch(/Enrichment & OSINT Data/);
  });
});
