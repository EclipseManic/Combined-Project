import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, AUTH_REQUIRED_EVENT, NETWORK_ERROR_DETAIL, clearRuntimeApiKey, getTaskStatus, lookupIOC, saveLookup, setRuntimeApiKey } from "../api";


describe("lookupIOC", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    clearRuntimeApiKey();
  });

  it.each(["d41d8cd98f00b204e9800998ecf8427e", "CVE-2024-3094"])(
    "sends %s using the API ioc field",
    async (value) => {
      const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(JSON.stringify({ task_id: "task-1", status: "pending" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

      await lookupIOC(value);

      expect(fetchMock).toHaveBeenCalledOnce();
      const [path, options] = fetchMock.mock.calls[0];
      expect(path).toBe("/api/lookup");
      expect(options?.body).toBe(JSON.stringify({ ioc: value }));
    },
  );

  it("can explicitly bypass the local cache for a live refresh", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ task_id: "task-refresh", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await lookupIOC("example.com", "domain", { refresh: true });

    const [, options] = fetchMock.mock.calls[0];
    expect(options?.body).toBe(JSON.stringify({ ioc: "example.com", ioc_type: "domain", refresh: true }));
  });

  it("adds the session API key to requests", async () => {
    setRuntimeApiKey("test-secret");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ task_id: "task-auth", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await lookupIOC("example.com");

    const [, options] = fetchMock.mock.calls[0];
    expect(new Headers(options?.headers).get("X-API-Key")).toBe("test-secret");
  });
});

describe("saveLookup", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts the ioc, type and task_id to /api/save", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await saveLookup("evil.example.com", "domain", "task-42");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [path, options] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/save");
    expect(options?.method).toBe("POST");
    expect(options?.body).toBe(
      JSON.stringify({ ioc: "evil.example.com", ioc_type: "domain", task_id: "task-42" }),
    );
  });
});

describe("request error reporting", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("surfaces the plain-text lookup rate limit with its Retry-After", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Rate limit exceeded. Try again later.", {
        status: 429,
        headers: { "Content-Type": "text/plain", "Retry-After": "60" },
      }),
    );

    const error = await lookupIOC("example.com").catch((err: unknown) => err);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(429);
    expect((error as ApiError).retryAfterSeconds).toBe(60);
    expect((error as ApiError).message).toBe("Rate limit exceeded. Try again later. Retry in 60s.");
  });

  it("uses the JSON detail of FastAPI errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "Unrecognizable IOC format", error_code: null }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const error = await lookupIOC("???").catch((err: unknown) => err);

    expect((error as ApiError).message).toBe("Unrecognizable IOC format");
    expect((error as ApiError).detail).toBe("Unrecognizable IOC format");
  });

  it("reports an unreachable backend as a network error", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));

    const error = await getTaskStatus("t1").catch((err: unknown) => err);

    expect((error as ApiError).status).toBe(0);
    expect((error as ApiError).detail).toBe(NETWORK_ERROR_DETAIL);
    expect((error as ApiError).message).toMatch(/Cannot reach the IOC Lookup Platform backend/);
  });

  it("asks for the API key on 401", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Invalid or missing API key", { status: 401 }));
    const listener = vi.fn();
    window.addEventListener(AUTH_REQUIRED_EVENT, listener);

    const error = await lookupIOC("example.com").catch((err: unknown) => err);

    window.removeEventListener(AUTH_REQUIRED_EVENT, listener);
    expect(listener).toHaveBeenCalledOnce();
    expect((error as ApiError).message).toMatch(/Authentication required/);
  });
});
