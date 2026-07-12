import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { basename, dirname, join } from "node:path";

import { AggregationError, type AggregationArtifacts, verifyAggregateFromBundleRecords } from "./aggregation.js";
import { createSignedAuditBundleManifest, verifyAuditBundleManifest } from "./bundles.js";
import { sha256Hex } from "./canonical.js";
import { keyIdFromPublicKey } from "./keys.js";
import {
  type ReceiptLedgerReader,
  type StoredPaymentFactsRow,
  type StoredReceiptRow,
  type StoredSettlementRow
} from "./ledger.js";
import {
  auditBundleManifestSchema,
  paymentFactsSchema,
  receiptSchema,
  settlementSchema,
  type AuditBundleManifest
} from "./schemas.js";
import { type Ed25519KeyPair } from "./keys.js";

export type AuditBundleErrorCode =
  | "BUNDLE_MISSING_RECORD"
  | "BUNDLE_EXTRANEOUS_RECORD"
  | "BUNDLE_DUPLICATE_RECORD"
  | "BUNDLE_ORDER_MISMATCH"
  | "MANIFEST_SIGNATURE_INVALID"
  | "SIGNATURE_KEY_MISMATCH"
  | "FACTS_CARDINALITY_INVALID"
  | "SETTLEMENT_CARDINALITY_INVALID"
  | "TOTALS_MISMATCH"
  | "SUMMARY_SIGNATURE_INVALID"
  | "RECEIPT_SIGNATURE_INVALID"
  | "FACTS_SIGNATURE_INVALID"
  | "SETTLEMENT_SIGNATURE_INVALID"
  | "SETTLEMENT_BINDING_INVALID";

export class AuditBundleError extends Error {
  constructor(
    readonly code: AuditBundleErrorCode,
    message: string
  ) {
    super(message);
  }
}

export interface WriteAuditBundleOptions {
  outputDir: string;
  force?: boolean;
  artifacts: AggregationArtifacts;
  publicKey: string;
  keyPair: Ed25519KeyPair;
  bundleId?: string;
  createdAt?: Date;
}

export interface AuditBundleVerificationResult {
  valid: boolean;
  code?: AuditBundleErrorCode | string;
  error?: string;
}

export function writeAuditBundle(options: WriteAuditBundleOptions): AuditBundleManifest {
  if (existsSync(options.outputDir) && options.force !== true) {
    throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Audit bundle output directory already exists");
  }

  const temporaryDir = join(dirname(options.outputDir), `.${randomUUID()}.tmp`);
  mkdirSync(temporaryDir, { recursive: false, mode: 0o700 });

  try {
    mkdirSync(join(temporaryDir, "receipts"));
    mkdirSync(join(temporaryDir, "facts"));
    mkdirSync(join(temporaryDir, "settlements"));

    const files = new Map<string, Buffer>();
    files.set("summary.json", jsonBytes(options.artifacts.summary));
    files.set("pubkey.json", jsonBytes({ public_key: options.publicKey, key_id: options.keyPair.keyId }));

    const sequenceByReceiptId = new Map(options.artifacts.receiptRows.map((row) => [row.receiptId, row.sequence]));
    for (const row of options.artifacts.receiptRows) {
      files.set(receiptFilePath("receipts", row.sequence, row.receiptId), Buffer.from(`${row.receiptJson}\n`, "utf8"));
    }
    for (const row of options.artifacts.paymentFactsRows) {
      const sequence = sequenceByReceiptId.get(row.receiptId);
      if (sequence === undefined) {
        throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Payment facts do not belong to the selected receipt range");
      }
      files.set(receiptFilePath("facts", sequence, row.receiptId), Buffer.from(`${row.factsJson}\n`, "utf8"));
    }
    for (const row of options.artifacts.settlementRows) {
      const sequence = sequenceByReceiptId.get(row.receiptId);
      if (sequence === undefined) {
        throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Settlement does not belong to the selected receipt range");
      }
      files.set(receiptFilePath("settlements", sequence, row.receiptId), Buffer.from(`${row.settlementJson}\n`, "utf8"));
    }

    for (const [path, content] of files) {
      const filePath = join(temporaryDir, path);
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, content, { mode: 0o600 });
    }

    const fileInventory = [...files.entries()]
      .map(([path, content]) => ({ path, sha256: sha256Hex(content) }))
      .sort((left, right) => compareText(left.path, right.path));
    const summaryBytes = files.get("summary.json");
    if (summaryBytes === undefined) {
      throw new Error("Audit bundle summary is missing");
    }
    const manifest = createSignedAuditBundleManifest({
      schema_version: "1.0",
      bundle_id: options.bundleId ?? randomUUID(),
      created_at: (options.createdAt ?? new Date()).toISOString(),
      receipts: options.artifacts.receiptRows.map((row) => ({
        receipt_id: row.receiptId,
        receipt_hash: row.receiptHash
      })),
      files: fileInventory,
      summary_sha256: sha256Hex(summaryBytes),
      keyPair: options.keyPair
    });
    writeFileSync(join(temporaryDir, "manifest.json"), jsonBytes(manifest), { mode: 0o600 });

    if (existsSync(options.outputDir)) {
      rmSync(options.outputDir, { force: true, recursive: true });
    }
    renameSync(temporaryDir, options.outputDir);
    return manifest;
  } catch (error) {
    rmSync(temporaryDir, { force: true, recursive: true });
    throw error;
  }
}

export function verifyAuditBundle(bundleDir: string, publicKey: string): AuditBundleVerificationResult {
  try {
    const manifest = readManifest(bundleDir, publicKey);
    verifyInventory(bundleDir, manifest);
    const summary = readJson(join(bundleDir, "summary.json"));
    const reader = readBundleLedger(bundleDir, manifest);
    const verification = verifyAggregateFromBundleRecords(reader, summary, publicKey);
    if (!verification.valid) {
      return fail(verification.code ?? "TOTALS_MISMATCH", verification.error ?? "Aggregate bundle verification failed");
    }
  } catch (error) {
    if (error instanceof AuditBundleError) {
      return fail(error.code, error.message);
    }
    if (error instanceof AggregationError) {
      return fail(error.code, error.message);
    }
    return fail("TOTALS_MISMATCH", error instanceof Error ? error.message : String(error));
  }

  return { valid: true };
}

function readManifest(bundleDir: string, publicKey: string): AuditBundleManifest {
  const manifestInput = readJson(join(bundleDir, "manifest.json"));
  const parsed = auditBundleManifestSchema.safeParse(manifestInput);
  if (!parsed.success) {
    throw new AuditBundleError("MANIFEST_SIGNATURE_INVALID", "Audit manifest does not match its schema");
  }
  if (parsed.data.key_id !== keyIdFromPublicKey(publicKey)) {
    throw new AuditBundleError("SIGNATURE_KEY_MISMATCH", "Audit manifest key does not match supplied public key");
  }
  if (!verifyAuditBundleManifest(parsed.data, publicKey)) {
    throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit manifest signature verification failed");
  }
  return parsed.data;
}

function verifyInventory(bundleDir: string, manifest: AuditBundleManifest): void {
  const manifestPaths = manifest.files.map((file) => file.path);
  if (new Set(manifestPaths).size !== manifestPaths.length) {
    throw new AuditBundleError("BUNDLE_DUPLICATE_RECORD", "Audit manifest lists the same file more than once");
  }
  if (!manifest.files.some((file) => file.path === "summary.json" && file.sha256 === manifest.summary_sha256)) {
    throw new AuditBundleError("TOTALS_MISMATCH", "Audit manifest summary hash does not match its inventory");
  }

  const actualPaths = listFiles(bundleDir).filter((path) => path !== "manifest.json");
  const expectedPaths = [...manifestPaths].sort(compareText);
  const unexpectedPaths = actualPaths.filter((path) => !expectedPaths.includes(path));
  const missingPaths = expectedPaths.filter((path) => !actualPaths.includes(path));
  if (
    unexpectedPaths.length > 0 &&
    missingPaths.length > 0 &&
    [...unexpectedPaths, ...missingPaths].every((path) => path.startsWith("receipts/"))
  ) {
    throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit receipt filenames no longer match signed order");
  }
  if (unexpectedPaths.length > 0 && hasDuplicateRecord(bundleDir, unexpectedPaths, actualPaths)) {
    throw new AuditBundleError("BUNDLE_DUPLICATE_RECORD", "Audit bundle contains a duplicate record");
  }
  if (unexpectedPaths.length > 0) {
    throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Audit bundle contains an unrelated file");
  }
  if (missingPaths.length > 0) {
    throw new AuditBundleError("BUNDLE_MISSING_RECORD", "Audit bundle is missing an expected file");
  }

  for (const file of manifest.files) {
    const actualHash = sha256Hex(readFileSync(join(bundleDir, file.path)));
    if (actualHash !== file.sha256) {
      if (file.path === "summary.json") {
        throw new AuditBundleError("TOTALS_MISMATCH", "Audit summary file differs from signed inventory");
      }
      if (file.path.startsWith("receipts/")) {
        throw new AuditBundleError("RECEIPT_SIGNATURE_INVALID", "Receipt file differs from signed inventory");
      }
      if (file.path.startsWith("facts/")) {
        throw new AuditBundleError("FACTS_SIGNATURE_INVALID", "Payment facts file differs from signed inventory");
      }
      if (file.path.startsWith("settlements/")) {
        throw new AuditBundleError("SETTLEMENT_BINDING_INVALID", "Settlement file differs from signed inventory");
      }
      throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit file differs from signed inventory");
    }
  }
}

function hasDuplicateRecord(bundleDir: string, unexpectedPaths: readonly string[], actualPaths: readonly string[]): boolean {
  const recordDirectories = ["receipts", "facts", "settlements"] as const;
  for (const directory of recordDirectories) {
    const expectedIds = new Set<string>();
    for (const path of actualPaths) {
      if (!path.startsWith(`${directory}/`) || unexpectedPaths.includes(path)) {
        continue;
      }
      const id = recordIdentity(directory, readFileSync(join(bundleDir, path), "utf8"));
      if (id !== null) {
        expectedIds.add(id);
      }
    }
    for (const path of unexpectedPaths) {
      if (!path.startsWith(`${directory}/`)) {
        continue;
      }
      const id = recordIdentity(directory, readFileSync(join(bundleDir, path), "utf8"));
      if (id !== null && expectedIds.has(id)) {
        return true;
      }
    }
  }
  return false;
}

function recordIdentity(directory: "receipts" | "facts" | "settlements", value: string): string | null {
  const parsed = parseJson(value);
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const field = directory === "facts" ? "facts_id" : directory === "settlements" ? "settlement_id" : "receipt_id";
  const id = (parsed as Record<string, unknown>)[field];
  return typeof id === "string" ? id : null;
}

function readBundleLedger(bundleDir: string, manifest: AuditBundleManifest): ReceiptLedgerReader {
  const receiptPaths = listFiles(join(bundleDir, "receipts"));
  if (receiptPaths.length !== manifest.receipts.length) {
    throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit receipt file count does not match manifest order");
  }

  const receiptRows: StoredReceiptRow[] = receiptPaths.map((path, index) => {
    const receiptJson = readFileSync(join(bundleDir, "receipts", path), "utf8").trim();
    const parsed = receiptSchema.safeParse(parseJson(receiptJson));
    const expected = manifest.receipts[index];
    if (!parsed.success || expected === undefined || parsed.data.receipt_id !== expected.receipt_id) {
      throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit receipt files do not match manifest order");
    }
    return {
      sequence: sequenceFromFileName(path),
      receiptId: parsed.data.receipt_id,
      receiptJson,
      receiptHash: expected.receipt_hash
    };
  });

  const factsRows = readFactsRows(bundleDir, receiptRows);
  const settlementRows = readSettlementRows(bundleDir, receiptRows);
  return new BundleLedger(receiptRows, factsRows, settlementRows);
}

function readFactsRows(bundleDir: string, receipts: readonly StoredReceiptRow[]): StoredPaymentFactsRow[] {
  const expectedPathById = new Map(receipts.map((receipt) => [receipt.receiptId, receiptFilePath("facts", receipt.sequence, receipt.receiptId)]));
  const paths = listFiles(join(bundleDir, "facts"));
  const rows: StoredPaymentFactsRow[] = [];
  for (const path of paths) {
    const factsJson = readFileSync(join(bundleDir, "facts", path), "utf8").trim();
    const parsed = paymentFactsSchema.safeParse(parseJson(factsJson));
    if (!parsed.success) {
      throw new AuditBundleError("FACTS_SIGNATURE_INVALID", "Payment facts file does not match schema");
    }
    const expectedPath = expectedPathById.get(parsed.data.receipt_id);
    if (expectedPath === undefined) {
      throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Payment facts reference an unrelated receipt");
    }
    if (path !== basename(expectedPath)) {
      throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Payment facts filename does not match receipt sequence");
    }
    rows.push({
      factsId: parsed.data.facts_id,
      receiptId: parsed.data.receipt_id,
      receiptHash: parsed.data.receipt_hash,
      factsJson
    });
  }
  if (new Set(rows.map((row) => row.receiptId)).size !== rows.length) {
    throw new AuditBundleError("BUNDLE_DUPLICATE_RECORD", "Audit bundle contains duplicate payment facts");
  }
  return rows;
}

function readSettlementRows(bundleDir: string, receipts: readonly StoredReceiptRow[]): StoredSettlementRow[] {
  const expectedPathById = new Map(receipts.map((receipt) => [receipt.receiptId, receiptFilePath("settlements", receipt.sequence, receipt.receiptId)]));
  const paths = listFiles(join(bundleDir, "settlements"));
  const rows: StoredSettlementRow[] = [];
  for (const path of paths) {
    const settlementJson = readFileSync(join(bundleDir, "settlements", path), "utf8").trim();
    const parsed = settlementSchema.safeParse(parseJson(settlementJson));
    if (!parsed.success) {
      throw new AuditBundleError("SETTLEMENT_SIGNATURE_INVALID", "Settlement file does not match schema");
    }
    const expectedPath = expectedPathById.get(parsed.data.receipt_id);
    if (expectedPath === undefined) {
      throw new AuditBundleError("BUNDLE_EXTRANEOUS_RECORD", "Settlement references an unrelated receipt");
    }
    if (path !== basename(expectedPath)) {
      throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Settlement filename does not match receipt sequence");
    }
    rows.push({
      settlementId: parsed.data.settlement_id,
      receiptId: parsed.data.receipt_id,
      receiptHash: parsed.data.receipt_hash,
      network: parsed.data.network,
      txHash: parsed.data.tx_hash,
      settlementJson
    });
  }
  if (new Set(rows.map((row) => row.receiptId)).size !== rows.length) {
    throw new AuditBundleError("BUNDLE_DUPLICATE_RECORD", "Audit bundle contains duplicate settlements");
  }
  return rows;
}

class BundleLedger implements ReceiptLedgerReader {
  private readonly factsByReceiptId: Map<string, StoredPaymentFactsRow>;
  private readonly settlementsByReceiptId: Map<string, StoredSettlementRow>;
  private readonly receiptsById: Map<string, StoredReceiptRow>;

  constructor(
    private readonly receiptRows: readonly StoredReceiptRow[],
    private readonly factsRows: readonly StoredPaymentFactsRow[],
    private readonly settlementRows: readonly StoredSettlementRow[]
  ) {
    this.factsByReceiptId = new Map(factsRows.map((row) => [row.receiptId, row]));
    this.settlementsByReceiptId = new Map(settlementRows.map((row) => [row.receiptId, row]));
    this.receiptsById = new Map(receiptRows.map((row) => [row.receiptId, row]));
  }

  getLastReceiptHash(): string | null {
    return this.receiptRows.at(-1)?.receiptHash ?? null;
  }

  getReceiptRowById(receiptId: string): StoredReceiptRow | null {
    return this.receiptsById.get(receiptId) ?? null;
  }

  listReceiptRows(): readonly StoredReceiptRow[] {
    return this.receiptRows;
  }

  getPaymentFactsRowByReceiptId(receiptId: string): StoredPaymentFactsRow | null {
    return this.factsByReceiptId.get(receiptId) ?? null;
  }

  listPaymentFactsRows(): readonly StoredPaymentFactsRow[] {
    return this.factsRows;
  }

  getSettlementRowByReceiptId(receiptId: string): StoredSettlementRow | null {
    return this.settlementsByReceiptId.get(receiptId) ?? null;
  }

  listSettlementRows(): readonly StoredSettlementRow[] {
    return this.settlementRows;
  }

  listAllowedReceipts() {
    return [];
  }
}

function receiptFilePath(directory: string, sequence: number, receiptId: string): string {
  return `${directory}/${String(sequence).padStart(12, "0")}-${receiptId}.json`;
}

function listFiles(root: string): string[] {
  if (!existsSync(root)) {
    return [];
  }
  const paths: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const entryPath = join(root, entry.name);
    if (entry.isDirectory()) {
      for (const descendant of listFiles(entryPath)) {
        paths.push(join(entry.name, descendant));
      }
    } else if (entry.isFile()) {
      paths.push(entry.name);
    }
  }
  return paths.sort(compareText);
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function readJson(path: string): unknown {
  return parseJson(readFileSync(path, "utf8"));
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new AuditBundleError("TOTALS_MISMATCH", "Audit bundle JSON is not parseable");
  }
}

function sequenceFromFileName(path: string): number {
  const match = /^(\d+)-[0-9a-f-]+\.json$/u.exec(path);
  if (match?.[1] === undefined) {
    throw new AuditBundleError("BUNDLE_ORDER_MISMATCH", "Audit receipt filename is invalid");
  }
  return Number(match[1]);
}

function compareText(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function fail(code: AuditBundleVerificationResult["code"], error: string): AuditBundleVerificationResult {
  return code === undefined ? { valid: false, error } : { valid: false, code, error };
}
