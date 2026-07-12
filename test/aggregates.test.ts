import { describe, expect, it } from "vitest";

import {
  createSignedAggregateSummary,
  generateEd25519KeyPair,
  merkleRoot,
  verifyAggregateSummary
} from "../src/index.js";

const hashes = ["0", "1", "2", "3", "4", "5"].map((character) => character.repeat(64));

describe("aggregate primitives", () => {
  it("matches RFC 6962 Merkle vectors for one through six leaves", () => {
    expect(merkleRoot(hashes.slice(0, 1))).toBe("7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9");
    expect(merkleRoot(hashes.slice(0, 2))).toBe("8ab671c69294e69917042ed794e5ea9dda18710ca307a65b986226344b87552a");
    expect(merkleRoot(hashes.slice(0, 3))).toBe("cfdd57c49cf0b23df41b9ff2fce70eed9d15fd0242a185dbdb5b918f8b140cce");
    expect(merkleRoot(hashes.slice(0, 5))).toBe("e68425ce96c5fff3a5f4ee6d49a0c3c84088038a9f27a568ca501ce69507c345");
    expect(merkleRoot(hashes.slice(0, 6))).toBe("65d68110552cf25209ec8a740bda6795af11a88fe382b1fe0c0e4fb2a3066437");
  });

  it("signs aggregate summaries and rejects altered fields", () => {
    const keyPair = generateEd25519KeyPair();
    const summary = createSignedAggregateSummary({
      schema_version: "1.0",
      aggregate_id: "00000000-0000-4000-8000-000000000030",
      created_at: "2026-06-10T22:00:00.000Z",
      range: {
        type: "receipt_id",
        from_id: "00000000-0000-4000-8000-000000000031",
        to_id: "00000000-0000-4000-8000-000000000031"
      },
      receipt_count: 1,
      decision_counts: { ALLOW: 1, DENY: 0 },
      reason_code_counts: {
        ALLOWED: 1,
        AMOUNT_EXCEEDS_PER_PAYMENT_MAX: 0,
        SESSION_BUDGET_EXCEEDED: 0,
        PAY_TO_NOT_ALLOWED: 0,
        HOST_NOT_ALLOWED: 0,
        REPEAT_PAYMENT_LOOP: 0,
        INTENT_INVALID: 0,
        POLICY_INVALID: 0
      },
      invalid_intent_count: 0,
      invalid_policy_count: 0,
      legacy_unproven_count: 0,
      totals: [
        {
          asset: "USDC",
          network: "base",
          settled_base_units: "0",
          unsettled_allow_base_units: "100"
        }
      ],
      first_receipt_hash: hashes[0] ?? "",
      last_receipt_hash: hashes[0] ?? "",
      merkle_root: merkleRoot(hashes.slice(0, 1)),
      keyPair
    });

    expect(verifyAggregateSummary(summary, keyPair.publicKey)).toBe(true);
    expect(verifyAggregateSummary({ ...summary, receipt_count: 2 }, keyPair.publicKey)).toBe(false);
    expect(verifyAggregateSummary({ ...summary, totals: [] }, keyPair.publicKey)).toBe(false);
  });
});
