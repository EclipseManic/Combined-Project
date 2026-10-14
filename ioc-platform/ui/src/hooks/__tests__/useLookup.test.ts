import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as Api from "../../services/api";

const mocks = vi.hoisted(() => ({
  lookupIOC: vi.fn(),
  getTaskStatus: vi.fn(),
  getTaskResult: vi.fn(),
  cancelTask: vi.fn(),
  saveLookup: vi.fn(),
  getRecentIOCResult: vi.fn(),
  getStoredLookup: vi.fn(),
}));

vi.mock("../../services/api", async (importOriginal) => {
  const actual = await importOriginal<typeof Api>();
  return { ...actual, ...mocks };
});

import { ApiError } from "../../services/api";
import { useLookup } from "../useLookup";

const RESULT_A = { input: "a.example", normalized: "a.example", ioc_type: "domain" };
const RESULT_B = { input: "b.example", normalized: "b.example", ioc_type: "domain" };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

describe("useLookup request flow", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
    mocks.cancelTask.mockResolvedValue({ task_id: "x", status: "cancelling" });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls status, then fetches the result once, without calling /api/save", async () => {
    mocks.lookupIOC.mockResolvedValue({ task_id: "t1", status: "pending", ioc_value: "a.example" });
    mocks.getTaskStatus
      .mockResolvedValueOnce({ task_id: "t1", status: "querying", progress: 40, stages: [], ioc_value: "a.example" })
      .mockResolvedValue({ task_id: "t1", status: "done", progress: 100, stages: [], ioc_value: "a.example" });
    mocks.getTaskResult.mockResolvedValue(RESULT_A);
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example"); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2500); });

    await waitFor(() => expect(result.current.state.status).toBe("done"));
    expect(mocks.getTaskResult).toHaveBeenCalledTimes(1);
    expect(mocks.saveLookup).not.toHaveBeenCalled();
  });

  it("never lets a stale lookup overwrite a newer one and cancels the superseded task", async () => {
    const first = deferred<unknown>();
    mocks.lookupIOC
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce({ task_id: "t2", status: "pending", ioc_value: "b.example" });
    mocks.getTaskStatus.mockImplementation(async (taskId: string) => ({ task_id: taskId, status: "done", progress: 100, stages: [], ioc_value: "" }));
    mocks.getTaskResult.mockImplementation(async (taskId: string) => (taskId === "t1" ? RESULT_A : RESULT_B));
    const { result } = renderHook(() => useLookup());

    let firstSubmit: Promise<void> = Promise.resolve();
    act(() => { firstSubmit = result.current.submit("a.example"); });
    await act(async () => { await result.current.submit("b.example"); });
    await act(async () => {
      first.resolve({ task_id: "t1", status: "pending", ioc_value: "a.example" });
      await firstSubmit;
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(2500); });

    await waitFor(() => expect(result.current.state.status).toBe("done"));
    expect(result.current.state.status === "done" && result.current.state.result.normalized).toBe("b.example");
    expect(mocks.cancelTask).toHaveBeenCalledWith("t1");
    expect(mocks.getTaskResult).not.toHaveBeenCalledWith("t1");
  });

  it("cancel stops polling, cancels the backend task and returns to idle", async () => {
    mocks.lookupIOC.mockResolvedValue({ task_id: "t3", status: "pending", ioc_value: "a.example" });
    mocks.getTaskStatus.mockResolvedValue({ task_id: "t3", status: "querying", progress: 10, stages: [], ioc_value: "a.example" });
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example"); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1200); });
    const pollsBeforeCancel = mocks.getTaskStatus.mock.calls.length;
    act(() => { result.current.cancel(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });

    expect(result.current.state.status).toBe("idle");
    expect(mocks.cancelTask).toHaveBeenCalledWith("t3");
    expect(mocks.getTaskStatus.mock.calls.length).toBe(pollsBeforeCancel);
  });

  it("shows the lookup rate-limit message and allows a retry", async () => {
    mocks.lookupIOC.mockRejectedValueOnce(new ApiError("Rate limit exceeded. Try again later. Retry in 60s.", 429, "Rate limit exceeded. Try again later.", 60));
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example", "domain"); });

    expect(result.current.state).toMatchObject({
      status: "error",
      error: "Rate limit exceeded. Try again later. Retry in 60s.",
      request: { value: "a.example", iocType: "domain" },
    });
  });

  it("reports a server-side analysis failure instead of spinning", async () => {
    mocks.lookupIOC.mockResolvedValue({ task_id: "t4", status: "pending", ioc_value: "a.example" });
    mocks.getTaskStatus.mockResolvedValue({ task_id: "t4", status: "error", error: "pipeline exploded", ioc_value: "a.example" });
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example"); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1200); });

    await waitFor(() => expect(result.current.state).toMatchObject({ status: "error", error: "pipeline exploded" }));
  });

  it("keeps waiting while the task is still queued (404 before first sighting)", async () => {
    mocks.lookupIOC.mockResolvedValue({ task_id: "t5", status: "pending", ioc_value: "a.example" });
    mocks.getTaskStatus
      .mockRejectedValueOnce(new ApiError("Task not found", 404, "Task not found"))
      .mockRejectedValueOnce(new ApiError("Task not found", 404, "Task not found"))
      .mockResolvedValue({ task_id: "t5", status: "done", progress: 100, stages: [], ioc_value: "a.example" });
    mocks.getTaskResult.mockResolvedValue(RESULT_A);
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example"); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1200); });
    expect(result.current.state).toMatchObject({ status: "loading", queued: true });
    await act(async () => { await vi.advanceTimersByTimeAsync(2500); });

    await waitFor(() => expect(result.current.state.status).toBe("done"));
  });

  it("offers a live lookup instead of silently running one when no stored copy exists", async () => {
    mocks.getRecentIOCResult.mockRejectedValue(new ApiError("No stored result found for this IOC", 404, "No stored result found for this IOC"));
    const { result } = renderHook(() => useLookup());

    let shown = true;
    await act(async () => { shown = await result.current.loadStored(7, "a.example", { isHistorical: true }, "domain"); });

    expect(shown).toBe(false);
    expect(mocks.lookupIOC).not.toHaveBeenCalled();
    expect(result.current.state).toMatchObject({ status: "error", storedOnly: true, request: { value: "a.example", iocType: "domain" } });
  });

  it("ignores a duplicate submit of the running lookup instead of cancelling it", async () => {
    mocks.lookupIOC.mockResolvedValue({ task_id: "t6", status: "pending", ioc_value: "a.example" });
    mocks.getTaskStatus.mockResolvedValue({ task_id: "t6", status: "querying", progress: 10, stages: [], ioc_value: "a.example" });
    const { result } = renderHook(() => useLookup());

    await act(async () => { await result.current.submit("a.example", "domain"); });
    await act(async () => { await result.current.submit("a.example", "domain"); });

    expect(mocks.lookupIOC).toHaveBeenCalledTimes(1);
    expect(mocks.cancelTask).not.toHaveBeenCalled();
    expect(result.current.state).toMatchObject({ status: "loading", taskId: "t6" });

    // An explicit refresh is a new lookup and replaces the running one.
    mocks.lookupIOC.mockResolvedValueOnce({ task_id: "t7", status: "pending", ioc_value: "a.example" });
    await act(async () => { await result.current.submit("a.example", "domain", true); });
    expect(mocks.cancelTask).toHaveBeenCalledWith("t6");
    expect(result.current.state).toMatchObject({ status: "loading", taskId: "t7" });
    act(() => { result.current.cancel(); });
  });
});
