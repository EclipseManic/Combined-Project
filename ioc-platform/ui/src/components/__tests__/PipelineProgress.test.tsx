import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PipelineProgress from "../PipelineProgress";

describe("PipelineProgress", () => {
  it("renders safely when an older API response omits progress details", () => {
    render(<PipelineProgress />);

    expect(screen.getByRole("progressbar")).toBeTruthy();
    expect(screen.getByText(/0\/0 stages/)).toBeTruthy();
  });
});
