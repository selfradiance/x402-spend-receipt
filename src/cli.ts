#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Command, CommanderError } from "commander";

import {
  evaluateAndRecord,
  generateEd25519KeyPair,
  keyIdFromPublicKey,
  receiptHash,
  SqliteReceiptLedger,
  verifyChain,
  verifyPaymentFacts,
  verifyReceipt,
  type Ed25519KeyPair
} from "./index.js";
import { createSignedSettlement } from "./settlements.js";
import { paymentFactsSchema, receiptSchema } from "./schemas.js";

interface CliStreams {
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
}

export interface RunCliOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  stdout?: Pick<NodeJS.WriteStream, "write">;
  stderr?: Pick<NodeJS.WriteStream, "write">;
}

interface CliContext {
  env: NodeJS.ProcessEnv;
  cwd: string;
  streams: CliStreams;
}

interface ConfigPaths {
  configDir: string;
  privateKeyPath: string;
  publicKeyPath: string;
  policyPath: string;
  ledgerPath: string;
}

const defaultPolicyTemplate = {
  max_per_payment_base_units: "1000000",
  session_budget_base_units: "10000000",
  pay_to_allowlist: ["replace-with-payment-address"],
  endpoint_host_allowlist: ["api.example.com"],
  repeat_payment_rule: {
    max_repeats: 2,
    window_seconds: 60
  },
  budget_mode: "all_allows"
};

export async function runCli(args: readonly string[], options: RunCliOptions = {}): Promise<number> {
  const streams = {
    stdout: options.stdout ?? process.stdout,
    stderr: options.stderr ?? process.stderr
  };
  const context: CliContext = {
    env: options.env ?? process.env,
    cwd: options.cwd ?? process.cwd(),
    streams
  };

  const program = new Command();
  program
    .name("x402-spend-receipt")
    .description("Local x402 policy checks with signed receipt records.")
    .exitOverride()
    .configureOutput({
      writeOut: (message) => streams.stdout.write(message),
      writeErr: (message) => streams.stderr.write(message)
    });

  program.command("init").description("Create local keys, policy template, and ledger database.").action(() => {
    initializeConfig(context);
  });

  program.command("check").argument("<intent.json>").description("Evaluate an intent and record a signed receipt.").action((intentPath: string) => {
    return checkIntent(context, intentPath);
  });

  program
    .command("verify")
    .argument("<receipt.json>")
    .requiredOption("--pubkey <key>", "base64 Ed25519 public key")
    .description("Verify one receipt signature offline.")
    .action((receiptPath: string, commandOptions: { pubkey: string }) => {
      verifyOneReceipt(context, receiptPath, commandOptions.pubkey);
    });

  program.command("verify-chain").description("Verify the local ledger hash chain and signatures.").action(() => {
    verifyLocalChain(context);
  });

  program.command("export").argument("<receipt_id>").description("Export one receipt with the public key.").action((receiptId: string) => {
    exportReceipt(context, receiptId);
  });

  program
    .command("record-settlement")
    .argument("<receipt_id>")
    .requiredOption("--tx <hash>", "EVM transaction hash")
    .requiredOption("--network <caip2>", "CAIP-2 network identifier")
    .description("Record a signed local settlement attestation for an ALLOW receipt.")
    .action((receiptId: string, commandOptions: { tx: string; network: string }) => {
      recordSettlement(context, receiptId, commandOptions);
    });

  try {
    await program.parseAsync([...args], { from: "user" });
    return process.exitCode === 1 ? 1 : 0;
  } catch (error) {
    if (error instanceof NewCliCommandError) {
      writeJson(streams.stdout, {
        ok: false,
        code: error.code,
        message: error.message
      });
      return 1;
    }

    if (error instanceof CliCommandError) {
      if (error.message.length > 0) {
        streams.stderr.write(`${error.message}\n`);
      }
      return error.exitCode;
    }

    if (error instanceof CommanderError) {
      return typeof error.exitCode === "number" ? error.exitCode : 1;
    }

    streams.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  } finally {
    process.exitCode = undefined;
  }
}

function initializeConfig(context: CliContext): void {
  const paths = configPaths(context.env);
  mkdirSync(paths.configDir, { recursive: true, mode: 0o700 });

  const keyPair = generateEd25519KeyPair();
  writeFileSync(paths.privateKeyPath, `${keyPair.privateKey}\n`, { mode: 0o600 });
  chmodSync(paths.privateKeyPath, 0o600);
  writeFileSync(paths.publicKeyPath, `${keyPair.publicKey}\n`, { mode: 0o644 });
  writeFileSync(paths.policyPath, `${JSON.stringify(defaultPolicyTemplate, null, 2)}\n`, { mode: 0o644 });

  const ledger = new SqliteReceiptLedger(paths.ledgerPath);
  ledger.close();

  writeJson(context.streams.stdout, {
    config_dir: paths.configDir,
    public_key: keyPair.publicKey,
    private_key_path: paths.privateKeyPath,
    policy_path: paths.policyPath,
    ledger_path: paths.ledgerPath
  });
}

function checkIntent(context: CliContext, intentPath: string): void {
  const paths = configPaths(context.env);
  const keyPair = readKeyPair(paths);
  const intent = readJsonFile(resolvePath(context.cwd, intentPath));
  const policy = readJsonFile(paths.policyPath);
  const ledger = new SqliteReceiptLedger(paths.ledgerPath);

  try {
    const result = evaluateAndRecord(intent, policy, {
      ledger,
      keyPair
    });

    writeJson(context.streams.stdout, {
      decision: result.decision,
      reason_code: result.reasonCode,
      receipt: result.receipt
    });

    if (result.decision === "DENY") {
      throw new CliCommandError("", 1);
    }
  } finally {
    ledger.close();
  }
}

function verifyOneReceipt(context: CliContext, receiptPath: string, publicKey: string): void {
  const receipt = readJsonFile(resolvePath(context.cwd, receiptPath));
  const valid = verifyReceipt(extractReceipt(receipt), publicKey.trim());

  writeJson(context.streams.stdout, { valid });
  if (!valid) {
    throw new CliCommandError("Receipt signature verification failed", 1);
  }
}

function verifyLocalChain(context: CliContext): void {
  const paths = configPaths(context.env);
  const publicKey = readTextFile(paths.publicKeyPath).trim();
  const ledger = new SqliteReceiptLedger(paths.ledgerPath);

  try {
    const result = verifyChain(ledger, publicKey);
    writeJson(context.streams.stdout, result);
    if (!result.valid) {
      throw new CliCommandError(result.error ?? "Ledger chain verification failed", 1);
    }
  } finally {
    ledger.close();
  }
}

function exportReceipt(context: CliContext, receiptId: string): void {
  const paths = configPaths(context.env);
  const publicKey = readTextFile(paths.publicKeyPath).trim();
  const ledger = new SqliteReceiptLedger(paths.ledgerPath);

  try {
    const row = ledger.getReceiptRowById(receiptId);
    if (row === null) {
      throw new CliCommandError(`Receipt not found: ${receiptId}`, 1);
    }

    writeJson(context.streams.stdout, {
      ...JSON.parse(row.receiptJson),
      public_key: publicKey
    });
  } finally {
    ledger.close();
  }
}

function recordSettlement(context: CliContext, receiptId: string, commandOptions: { tx: string; network: string }): void {
  const normalizedTxHash = normalizeTransactionHash(commandOptions.tx);
  if (normalizedTxHash === null) {
    throw new NewCliCommandError("INVALID_TX_HASH", "Transaction hash must be 0x followed by 64 hexadecimal characters");
  }
  if (!isCaip2Network(commandOptions.network)) {
    throw new NewCliCommandError("INVALID_NETWORK", "Network must be a CAIP-2 identifier");
  }

  const paths = configPaths(context.env);
  const keyPair = readKeyPair(paths);
  const ledger = new SqliteReceiptLedger(paths.ledgerPath);

  try {
    const receiptRow = ledger.getReceiptRowById(receiptId);
    if (receiptRow === null) {
      throw new NewCliCommandError("RECEIPT_NOT_FOUND", "Receipt was not found");
    }

    const receipt = parseStoredReceipt(receiptRow.receiptJson, receiptRow.receiptHash, keyPair.publicKey);
    if (receipt.decision !== "ALLOW") {
      throw new NewCliCommandError("SETTLEMENT_ON_DENY", "Only ALLOW receipts can be settled");
    }

    const factsRow = ledger.getPaymentFactsRowByReceiptId(receipt.receipt_id);
    if (factsRow === null) {
      throw new NewCliCommandError("NO_PAYMENT_FACTS", "Receipt has no signed payment facts");
    }
    const facts = parseStoredPaymentFacts(factsRow.factsJson, receipt, keyPair.publicKey);

    const chainVerification = verifyChain(ledger, keyPair.publicKey);
    if (!chainVerification.valid) {
      throw new NewCliCommandError("CHAIN_INVALID", "Local receipt chain verification failed");
    }

    const mappedNetwork = mapFactsNetwork(facts.network);
    if (mappedNetwork === null) {
      throw new NewCliCommandError("SETTLEMENT_NETWORK_UNMAPPED", "Payment facts network cannot be mapped to CAIP-2");
    }
    if (mappedNetwork !== commandOptions.network) {
      throw new NewCliCommandError("SETTLEMENT_NETWORK_MISMATCH", "Settlement network does not match payment facts");
    }

    if (ledger.getSettlementRowByReceiptId(receipt.receipt_id) !== null) {
      throw new NewCliCommandError("ALREADY_SETTLED", "Receipt already has a settlement record");
    }
    if (ledger.listSettlementRows().some((settlement) => settlement.network === commandOptions.network && settlement.txHash === normalizedTxHash)) {
      throw new NewCliCommandError("TX_ALREADY_LINKED", "Transaction hash is already linked to another receipt");
    }

    const settlement = createSignedSettlement({
      settlementId: randomUUID(),
      timestamp: new Date().toISOString(),
      receiptId: receipt.receipt_id,
      receiptHash: receiptRow.receiptHash,
      txHash: normalizedTxHash,
      network: commandOptions.network,
      keyPair
    });

    try {
      ledger.appendSettlement(settlement);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("settlements.receipt_id")) {
        throw new NewCliCommandError("ALREADY_SETTLED", "Receipt already has a settlement record");
      }
      if (message.includes("settlements.network, settlements.tx_hash")) {
        throw new NewCliCommandError("TX_ALREADY_LINKED", "Transaction hash is already linked to another receipt");
      }
      throw error;
    }

    writeJson(context.streams.stdout, { ok: true, settlement });
  } finally {
    ledger.close();
  }
}

function configPaths(env: NodeJS.ProcessEnv): ConfigPaths {
  const configRoot = env.XDG_CONFIG_HOME ?? join(env.HOME ?? homedir(), ".config");
  const configDir = join(configRoot, "x402-spend-receipt");

  return {
    configDir,
    privateKeyPath: join(configDir, "ed25519.private.key"),
    publicKeyPath: join(configDir, "ed25519.public.key"),
    policyPath: join(configDir, "policy.json"),
    ledgerPath: join(configDir, "ledger.sqlite")
  };
}

function readKeyPair(paths: ConfigPaths): Ed25519KeyPair {
  const publicKey = readTextFile(paths.publicKeyPath).trim();
  const privateKey = readTextFile(paths.privateKeyPath).trim();

  return {
    publicKey,
    privateKey,
    keyId: keyIdFromPublicKey(publicKey)
  };
}

function readJsonFile(path: string): unknown {
  return JSON.parse(readTextFile(path));
}

function readTextFile(path: string): string {
  return readFileSync(path, "utf8");
}

function resolvePath(cwd: string, path: string): string {
  return resolve(cwd, path);
}

function extractReceipt(value: unknown): unknown {
  if (typeof value === "object" && value !== null && "receipt" in value) {
    return value.receipt;
  }

  if (typeof value === "object" && value !== null && "public_key" in value) {
    const receipt: Record<string, unknown> = { ...(value as Record<string, unknown>) };
    delete receipt.public_key;
    return receipt;
  }

  return value;
}

function writeJson(stream: Pick<NodeJS.WriteStream, "write">, value: unknown): void {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function parseStoredReceipt(receiptJson: string, storedHash: string, publicKey: string) {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(receiptJson);
  } catch {
    throw new NewCliCommandError("RECEIPT_SIGNATURE_INVALID", "Stored receipt is not valid signed JSON");
  }

  const parsedReceipt = receiptSchema.safeParse(parsedJson);
  if (!parsedReceipt.success || receiptHash(parsedReceipt.data) !== storedHash || !verifyReceipt(parsedReceipt.data, publicKey)) {
    throw new NewCliCommandError("RECEIPT_SIGNATURE_INVALID", "Stored receipt signature verification failed");
  }

  return parsedReceipt.data;
}

function parseStoredPaymentFacts(factsJson: string, receipt: ReturnType<typeof parseStoredReceipt>, publicKey: string) {
  let parsedFacts: unknown;
  try {
    parsedFacts = JSON.parse(factsJson);
  } catch {
    throw new NewCliCommandError("FACTS_SIGNATURE_INVALID", "Stored payment facts are not valid signed JSON");
  }

  const parsed = paymentFactsSchema.safeParse(parsedFacts);
  if (
    !parsed.success ||
    !verifyPaymentFacts(parsed.data, publicKey) ||
    parsed.data.receipt_id !== receipt.receipt_id ||
    parsed.data.receipt_hash !== receiptHash(receipt)
  ) {
    throw new NewCliCommandError("FACTS_SIGNATURE_INVALID", "Stored payment facts signature verification failed");
  }

  return parsed.data;
}

function normalizeTransactionHash(value: string): string | null {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value)) {
    return null;
  }

  return value.toLowerCase();
}

function isCaip2Network(value: string): boolean {
  return /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/u.test(value);
}

function mapFactsNetwork(network: string): string | null {
  if (isCaip2Network(network)) {
    return network;
  }
  if (network === "base") {
    return "eip155:8453";
  }
  if (network === "base-sepolia") {
    return "eip155:84532";
  }
  return null;
}

class CliCommandError extends Error {
  constructor(
    message: string,
    readonly exitCode: number
  ) {
    super(message);
  }
}

class NewCliCommandError extends Error {
  constructor(
    readonly code: string,
    message: string
  ) {
    super(message);
  }
}

if (process.argv[1] !== undefined && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  runCli(process.argv.slice(2)).then((exitCode) => {
    process.exitCode = exitCode;
  });
}
