import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Tag from "../Tag";

describe("Tag", () => {
  it("renders the label text", () => {
    render(<Tag label="malicious" />);
    expect(screen.getByText("malicious")).toBeTruthy();
  });
});
