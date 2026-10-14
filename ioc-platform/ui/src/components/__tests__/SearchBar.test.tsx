import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import SearchBar from "../SearchBar";

describe("SearchBar", () => {
  it.each([
    ["eclipsemanic.me", "eclipsemanic.me"],
    ["2606:4700:4700::1111", "2606:4700:4700::1111"],
    ["hxxps://example[.]com/", "https://example.com/"],
  ])("submits %s as %s", (value, expected) => {
    const onSearch = vi.fn();
    render(<SearchBar onSearch={onSearch} />);

    fireEvent.change(screen.getByLabelText("Search IOC"), { target: { value } });
    fireEvent.click(screen.getByLabelText("Submit search"));

    expect(onSearch).toHaveBeenCalledWith(expected);
    expect(screen.queryByText("Unrecognized IOC format")).toBeNull();
  });

  it("submits only a password digest when Web Crypto succeeds", async () => {
    const originalCrypto = window.crypto;
    const digest = vi.fn().mockResolvedValue(Uint8Array.from({ length: 20 }, () => 0xab).buffer);
    Object.defineProperty(window, "crypto", {
      configurable: true,
      value: { subtle: { digest } },
    });

    try {
      const onSearch = vi.fn();
      render(<SearchBar onSearch={onSearch} />);
      fireEvent.change(screen.getByLabelText("IOC type"), { target: { value: "password" } });
      fireEvent.change(screen.getByLabelText("Search IOC"), { target: { value: "S3cret!" } });
      fireEvent.click(screen.getByLabelText("Submit search"));

      await waitFor(() => expect(onSearch).toHaveBeenCalledTimes(1));
      expect(onSearch).toHaveBeenCalledWith("ab".repeat(20), "password_sha1");
      expect(onSearch).not.toHaveBeenCalledWith("S3cret!", "password_sha1");
    } finally {
      Object.defineProperty(window, "crypto", { configurable: true, value: originalCrypto });
    }
  });

  it("preserves an explicitly prehashed password on route reload", () => {
    const onSearch = vi.fn();
    const digest = "a".repeat(40);
    render(<SearchBar onSearch={onSearch} initialValue={digest} initialType="password_sha1" />);

    fireEvent.click(screen.getByLabelText("Submit search"));

    expect(onSearch).toHaveBeenCalledWith(digest, "password_sha1");
  });

  it.each(["S3cret!", "user@example.com", "secret.example.com"])("does not auto-submit ambiguous credential input %s", (value) => {
    const onSearch = vi.fn();
    render(<SearchBar onSearch={onSearch} />);
    fireEvent.change(screen.getByLabelText("Search IOC"), { target: { value } });
    fireEvent.click(screen.getByLabelText("Submit search"));

    expect(onSearch).not.toHaveBeenCalled();
    expect(screen.getByText("Select an IOC type or Password / Credential for ambiguous input")).toBeTruthy();
  });

  it("does not submit plaintext when Web Crypto is unavailable", async () => {
    const originalCrypto = window.crypto;
    Object.defineProperty(window, "crypto", { configurable: true, value: {} });

    try {
      const onSearch = vi.fn();
      render(<SearchBar onSearch={onSearch} />);
      fireEvent.change(screen.getByLabelText("IOC type"), { target: { value: "password" } });
      fireEvent.change(screen.getByLabelText("Search IOC"), { target: { value: "S3cret!" } });
      fireEvent.click(screen.getByLabelText("Submit search"));

      await waitFor(() => expect(screen.getByText("Secure password hashing is unavailable in this browser")).toBeTruthy());
      expect(onSearch).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "crypto", { configurable: true, value: originalCrypto });
    }
  });
});
