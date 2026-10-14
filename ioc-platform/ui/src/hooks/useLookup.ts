import { useCallback, useEffect, useRef, useState } from "react";
import type { LookupResponse, StageInfo } from "../services/api";
import {
  ApiError,
  NETWORK_ERROR_DETAIL,
  TIMEOUT_DETAIL,
  cancelTask,
  errorMessage,
  getRecentIOCResult,
  getStoredLookup,
  getTaskResult,
  getTaskStatus,
  lookupIOC,
} from "../services/api";

export interface ResultSourceMeta {
  isHistorical?: boolean;
  fromBatch?: boolean;
  batchId?: string;
  historyId?: number;
  scannedAt?: string | null;
}

export interface LookupRequest {
  value: string;
  iocType?: string;
  refresh?: boolean;
}

export type LookupState =
  | { status: "idle" }
  | { status: "loading"; progress: number; stages: StageInfo[]; taskId: string; queued?: boolean; message?: string }
  | { status: "done"; result: LookupResponse; meta?: ResultSourceMeta }
  | { status: "error"; error: string; request?: LookupRequest; storedOnly?: boolean };

/** Poll cadence while an analysis is running. */
export const POLL_INTERVAL_MS = 1000;
/** Consecutive transient poll failures (network, 5xx, client timeout) tolerated before giving up. */
export const MAX_TRANSIENT_POLL_FAILURES = 20;
/** How long a task may stay unknown to the server (still queued behind other lookups) before we give up. */
export const MAX_QUEUED_MS = 10 * 60_000;
/** Absolute ceiling for one lookup, far above the backend per-IOC deadline. */
export const MAX_LOOKUP_MS = 20 * 60_000;

const TERMINAL_FAILURES = new Set(["error", "cancelled", "failed"]);

function isTransient(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.detail === TIMEOUT_DETAIL ||
      error.detail === NETWORK_ERROR_DETAIL ||
      error.status === 0 ||
      error.status === 502 ||
      error.status === 503 ||
      error.status === 504)
  );
}

function sameLoadingState(
  prev: LookupState,
  taskId: string,
  update: Partial<Extract<LookupState, { status: "loading" }>>,
): LookupState {
  if (prev.status !== "loading" || prev.taskId !== taskId) return prev;
  return { ...prev, ...update };
}

/**
 * Drives a single IOC lookup: submit -> poll task status -> fetch result.
 *
 * Every asynchronous step is tagged with a generation number. Starting a new
 * lookup, cancelling, resetting or loading a stored result bumps the generation,
 * so a late response from an older lookup can never overwrite the newer one. The
 * superseded backend task is cancelled so it stops consuming provider quota.
 */
export function useLookup() {
  const [state, setState] = useState<LookupState>({ status: "idle" });
  const pollingRef = useRef<number | null>(null);
  const generationRef = useRef(0);
  const activeTaskIdRef = useRef<string | null>(null);
  const lastRequestRef = useRef<LookupRequest | null>(null);
  /** The lookup currently submitted or running (cleared when it reaches a terminal state). */
  const inFlightRef = useRef<LookupRequest | null>(null);

  const stopPolling = useCallback(() => {
    generationRef.current += 1;
    inFlightRef.current = null;
    if (pollingRef.current !== null) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }
    return generationRef.current;
  }, []);

  /** Cancel the running backend task (if any) without touching UI state. */
  const abandonActiveTask = useCallback(() => {
    const taskId = activeTaskIdRef.current;
    activeTaskIdRef.current = null;
    if (taskId) {
      cancelTask(taskId).catch((error) => console.debug("Task cancellation failed", error));
    }
  }, []);

  // Unmount: stop polling only. The backend still finishes and persists the
  // analysis, so it shows up in History instead of being silently discarded.
  useEffect(() => () => { stopPolling(); }, [stopPolling]);

  const loadResult = useCallback((result: LookupResponse, meta?: ResultSourceMeta) => {
    stopPolling();
    abandonActiveTask();
    setState({ status: "done", result, meta });
  }, [abandonActiveTask, stopPolling]);

  /**
   * Show a stored (history) result without running providers. When no stored
   * copy exists the analyst is offered a live lookup instead of one being started
   * silently (a live lookup spends provider quota). Returns true when a stored
   * result was shown.
   */
  const loadStored = useCallback(async (iocId?: number, iocValue?: string, meta?: ResultSourceMeta, iocType?: string) => {
    abandonActiveTask();
    const generation = stopPolling();
    setState({ status: "loading", progress: 0, stages: [], taskId: "", message: "Loading stored analysis…" });
    try {
      let result: LookupResponse | null = null;
      if (iocId) {
        result = await getRecentIOCResult(iocId);
      } else if (iocValue) {
        result = await getStoredLookup(iocValue);
      }
      if (generation !== generationRef.current) return false;
      if (result) {
        const createdAt = (result as LookupResponse & { created_at?: string | null }).created_at;
        setState({
          status: "done",
          result,
          meta: { ...meta, isHistorical: true, scannedAt: meta?.scannedAt || createdAt || null },
        });
        return true;
      }
      setState({
        status: "error",
        error: "No stored analysis was found for this indicator.",
        request: iocValue ? { value: iocValue, iocType } : undefined,
        storedOnly: true,
      });
      return false;
    } catch (error) {
      if (generation !== generationRef.current) return false;
      const missing = error instanceof ApiError && error.status === 404;
      setState({
        status: "error",
        error: missing ? "No stored analysis was found for this indicator." : `Could not load the stored analysis: ${errorMessage(error)}`,
        request: iocValue ? { value: iocValue, iocType } : undefined,
        storedOnly: true,
      });
      return false;
    }
  }, [abandonActiveTask, stopPolling]);

  const submit = useCallback(async (value: string, iocType?: string, refresh = false) => {
    const running = inFlightRef.current;
    if (!refresh && running && running.value === value && (running.iocType ?? "") === (iocType ?? "")) {
      // The same lookup is already running (double submit, route re-sync). The
      // backend joins identical submissions to one task, so cancelling and
      // resubmitting here would cancel the very task we are about to follow.
      return;
    }
    abandonActiveTask();
    const generation = stopPolling();
    const request: LookupRequest = { value, iocType, refresh };
    lastRequestRef.current = request;
    inFlightRef.current = request;
    setState({ status: "loading", progress: 0, stages: [], taskId: "", message: "Submitting lookup…" });

    let taskId: string;
    try {
      const task = await lookupIOC(value, iocType, { refresh });
      taskId = task.task_id;
      if (generation !== generationRef.current) {
        // Superseded while the POST was in flight: do not leave it running
        // (unless the newer lookup was joined to this same task).
        if (activeTaskIdRef.current !== taskId) {
          cancelTask(taskId).catch((error) => console.debug("Task cancellation failed", error));
        }
        return;
      }
      activeTaskIdRef.current = taskId;
      setState({
        status: "loading",
        progress: task.progress ?? 0,
        stages: task.stages ?? [],
        taskId,
        message: undefined,
      });
    } catch (error) {
      if (generation === generationRef.current) {
        inFlightRef.current = null;
        setState({ status: "error", error: errorMessage(error, "Lookup failed"), request });
      }
      return;
    }

    const startedAt = Date.now();
    let transientFailures = 0;
    let seenOnServer = false;

    const fail = (message: string) => {
      if (generation !== generationRef.current) return;
      stopPolling();
      if (activeTaskIdRef.current === taskId) activeTaskIdRef.current = null;
      setState({ status: "error", error: message, request });
    };

    const schedule = () => {
      if (generation !== generationRef.current) return;
      pollingRef.current = window.setTimeout(() => { void poll(); }, POLL_INTERVAL_MS);
    };

    const fetchResult = async () => {
      const result = await getTaskResult(taskId);
      if (generation !== generationRef.current) return;
      stopPolling();
      if (activeTaskIdRef.current === taskId) activeTaskIdRef.current = null;
      // The pipeline persists every completed analysis itself; no /api/save call
      // is needed (it could re-run a full paid lookup if the task had expired).
      setState({ status: "done", result });
    };

    const poll = async () => {
      if (generation !== generationRef.current) return;
      if (Date.now() - startedAt > MAX_LOOKUP_MS) {
        fail("The analysis did not finish in time. The server may be overloaded; try again later.");
        return;
      }
      try {
        const status = await getTaskStatus(taskId);
        if (generation !== generationRef.current) return;
        seenOnServer = true;
        transientFailures = 0;
        if (status.status === "done") {
          await fetchResult();
          return;
        }
        if (TERMINAL_FAILURES.has(status.status)) {
          fail(status.error || (status.status === "cancelled" ? "The analysis was cancelled." : "The analysis failed on the server."));
          return;
        }
        setState((prev) => sameLoadingState(prev, taskId, {
          progress: status.progress ?? (prev.status === "loading" ? prev.progress : 0),
          stages: status.stages ?? (prev.status === "loading" ? prev.stages : []),
          queued: false,
          message: undefined,
        }));
      } catch (error) {
        if (generation !== generationRef.current) return;
        if (error instanceof ApiError && error.status === 425) {
          // Status said done but the result is not materialized yet: try again.
        } else if (error instanceof ApiError && error.status === 404 && !seenOnServer) {
          // The server registers a task only once it leaves the lookup queue.
          if (Date.now() - startedAt > MAX_QUEUED_MS) {
            fail("The lookup stayed queued for too long. Other analyses may be stuck; try again later.");
            return;
          }
          setState((prev) => sameLoadingState(prev, taskId, { queued: true, message: "Queued — waiting for a free analysis slot…" }));
        } else if (error instanceof ApiError && error.status === 404) {
          fail("The server no longer knows this analysis (it may have restarted). Run the lookup again.");
          return;
        } else if (isTransient(error)) {
          transientFailures += 1;
          if (transientFailures > MAX_TRANSIENT_POLL_FAILURES) {
            fail(`Lost contact with the backend while the analysis was running: ${errorMessage(error)}`);
            return;
          }
          setState((prev) => sameLoadingState(prev, taskId, { message: "Connection problem — retrying…" }));
        } else {
          fail(errorMessage(error, "Lookup failed"));
          return;
        }
      }
      schedule();
    };

    schedule();
  }, [abandonActiveTask, stopPolling]);

  /** Stop the running analysis (backend task included) and return to idle. */
  const cancel = useCallback(() => {
    stopPolling();
    abandonActiveTask();
    setState({ status: "idle" });
  }, [abandonActiveTask, stopPolling]);

  /** Re-run the last submitted lookup (used by the error panel). */
  const retry = useCallback(() => {
    const last = lastRequestRef.current;
    if (!last) return false;
    void submit(last.value, last.iocType, last.refresh);
    return true;
  }, [submit]);

  const reset = cancel;

  return { state, submit, reset, cancel, retry, loadResult, loadStored };
}
