import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson, canonicalSha256Hex, sha256Hex } from "../src/index.js";

describe("canonical JSON", () => {
  it("recursively sorts object keys and removes whitespace", () => {
    const left = {
      z: true,
      a: {
        c: "third",
        b: ["second", { y: 2, x: 1 }]
      }
    };

    const right = {
      a: {
        b: ["second", { x: 1, y: 2 }],
        c: "third"
      },
      z: true
    };

    expect(canonicalJson(left)).toBe('{"a":{"b":["second",{"x":1,"y":2}],"c":"third"},"z":true}');
    expect(canonicalJson(left)).toBe(canonicalJson(right));
  });

  it("hashes canonical JSON with SHA-256 hex", () => {
    const value = { b: 2, a: 1 };
    const expected = createHash("sha256").update('{"a":1,"b":2}', "utf8").digest("hex");

    expect(canonicalSha256Hex(value)).toBe(expected);
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("returns the same digest when the same input is serialized twice", () => {
    const value = {
      method: "x402",
      amount_base_units: "1000000",
      endpoint_url: "https://api.example.com/metered"
    };

    expect(canonicalSha256Hex(value)).toBe(canonicalSha256Hex(value));
  });

  it("returns the same digest for the same data with different key order", () => {
    const first = {
      z: true,
      a: {
        c: "third",
        b: ["second", { y: 2, x: 1 }]
      }
    };

    const second = {
      a: {
        b: ["second", { x: 1, y: 2 }],
        c: "third"
      },
      z: true
    };

    expect(canonicalSha256Hex(first)).toBe(canonicalSha256Hex(second));
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalJson({ bad: Number.NaN })).toThrow("non-finite");
    expect(() => canonicalJson({ bad: Number.POSITIVE_INFINITY })).toThrow("non-finite");
  });
});
