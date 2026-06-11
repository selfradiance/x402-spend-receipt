import { describe, expect, it } from "vitest";

import { reasonCodes } from "../src/index.js";

describe("scaffold", () => {
  it("exports public library symbols", () => {
    expect(reasonCodes).toContain("ALLOWED");
  });
});
