#!/usr/bin/env node

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { Command, CommanderError } from "commander";

import {
  evaluateAndRecord,
  generateEd25519KeyPair,
  keyIdFromPublicKey,
  SqliteReceiptLedger,
  verifyChain,
  verifyReceipt,
  type Ed25519KeyPair
} from "./index.js";

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
  }
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

  try {
    await program.parseAsync([...args], { from: "user" });
    return process.exitCode === 1 ? 1 : 0;
  } catch (error) {
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

class CliCommandError extends Error {
  constructor(
    message: string,
    readonly exitCode: number
  ) {
    super(message);
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli(process.argv.slice(2)).then((exitCode) => {
    process.exitCode = exitCode;
  });
}
