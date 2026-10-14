import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LookupState } from "../../hooks/useLookup";

const hook = vi.hoisted(() => ({
  state: { status: "idle" } as LookupState,
  submit: vi.fn(),
  reset: vi.fn(),
  cancel: vi.fn(),
  retry: vi.fn(),
  loadResult: vi.fn(),
  loadStored: vi.fn(async () => true),
}));

vi.mock("../../hooks/useLookup", () => ({ useLookup: () => hook }));
vi.mock("../../components/SourceCoveragePanel", () => ({ default: () => null }));
vi.mock("../../components/PrivacyNotice", () => ({ default: () => null }));

import HomePage from "../HomePage";

describe("HomePage lookup states", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 404 }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    hook.state = { status: "idle" };
  });

  it("offers a working cancel button while a lookup runs", () => {
    hook.state = { status: "loading", progress: 20, stages: [], taskId: "t1" };
    render(<HomePage />);
    fireEvent.click(screen.getByRole("button", { name: /cancel lookup/i }));
    expect(hook.cancel).toHaveBeenCalledOnce();
  });

  it("shows the error and retries the same request", () => {
    hook.state = { status: "error", error: "Rate limit exceeded. Retry in 60s.", request: { value: "example.com", iocType: "domain", refresh: true } };
    render(<HomePage />);
    expect(screen.getByRole("alert").textContent).toContain("Rate limit exceeded. Retry in 60s.");
    fireEvent.click(screen.getByRole("button", { name: /retry lookup/i }));
    expect(hook.submit).toHaveBeenCalledWith("example.com", "domain", true);
  });

  it("reopens a history entry from storage without starting a live lookup", () => {
    render(<HomePage initialValue="8.8.8.8" initialType="ipv4" historyId={7} isHistorical />);
    expect(hook.loadStored).toHaveBeenCalledWith(7, "8.8.8.8", expect.objectContaining({ isHistorical: true, historyId: 7 }), "ipv4");
    expect(hook.submit).not.toHaveBeenCalled();
  });
});
