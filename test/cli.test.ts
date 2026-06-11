import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];

const validIntent = {
  method: "x402",
  endpoint_url: "https://api.example.com/metered",
  pay_to: "0xabc123",
  asset: "USDC",
  network: "base",
  amount_base_units: "100",
  agent_urn: "urn:agent:demo"
};

const validPolicy = {
  max_per_payment_base_units: "100",
  session_budget_base_units: "250",
  pay_to_allowlist: ["0xabc123"],
  endpoint_host_allowlist: ["api.example.com"],
  repeat_payment_rule: {
    max_repeats: 10,
    window_seconds: 60
  }
};

afterEach(() => {
  for (const tempDir of tempDirs.splice(0)) {
    rmSync(tempDir, { force: true, recursive: true });
  }
});

function tempWorkspace(): { root: string; configRoot: string; env: NodeJS.ProcessEnv } {
  const root = mkdtempSync(join(tmpdir(), "x402-spend-receipt-cli-"));
  const configRoot = join(root, "config");
  tempDirs.push(root);

  return {
    root,
    configRoot,
    env: {
      ...process.env,
      XDG_CONFIG_HOME: configRoot,
      HOME: root
    }
  };
}

function configDir(configRoot: string): string {
  return join(configRoot, "x402-spend-receipt");
}

function capture() {
  let stdout = "";
  let stderr = "";

  return {
    stdout: {
      write: (chunk: string) => {
        stdout += chunk;
        return true;
      }
    },
    stderr: {
      write: (chunk: string) => {
        stderr += chunk;
        return true;
      }
    },
    readStdout: () => stdout,
    readStderr: () => stderr
  };
}

async function run(args: readonly string[], workspace = tempWorkspace()) {
  const output = capture();
  const exitCode = await runCli(args, {
    cwd: workspace.root,
    env: workspace.env,
    stdout: output.stdout,
    stderr: output.stderr
  });

  return {
    ...workspace,
    exitCode,
    stdout: output.readStdout(),
    stderr: output.readStderr()
  };
}

async function initializedWorkspace() {
  const workspace = tempWorkspace();
  const init = await run(["init"], workspace);
  writeFileSync(join(configDir(workspace.configRoot), "policy.json"), `${JSON.stringify(validPolicy, null, 2)}\n`);

  return {
    ...workspace,
    init
  };
}

describe("CLI", () => {
  it("init creates local keys, a policy template, and the ledger database", async () => {
    const result = await run(["init"]);
    const localConfigDir = configDir(result.configRoot);

    expect(result.exitCode).toBe(0);
    expect(statSync(join(localConfigDir, "ed25519.private.key")).mode & 0o777).toBe(0o600);
    expect(statSync(join(localConfigDir, "ed25519.public.key")).isFile()).toBe(true);
    expect(statSync(join(localConfigDir, "policy.json")).isFile()).toBe(true);
    expect(statSync(join(localConfigDir, "ledger.sqlite")).isFile()).toBe(true);
  });

  it("check exits 0 on ALLOW and prints the decision plus receipt JSON", async () => {
    const workspace = await initializedWorkspace();
    const intentPath = join(workspace.root, "intent.json");
    writeFileSync(intentPath, `${JSON.stringify(validIntent)}\n`);

    const result = await run(["check", intentPath], workspace);
    const output = JSON.parse(result.stdout) as { decision: string; receipt: { receipt_id: string } };

    expect(result.exitCode).toBe(0);
    expect(output.decision).toBe("ALLOW");
    expect(output.receipt.receipt_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
    );
  });

  it("check exits 1 on DENY", async () => {
    const workspace = await initializedWorkspace();
    const intentPath = join(workspace.root, "intent.json");
    writeFileSync(intentPath, `${JSON.stringify({ ...validIntent, amount_base_units: "101" })}\n`);

    const result = await run(["check", intentPath], workspace);
    const output = JSON.parse(result.stdout) as { decision: string; reason_code: string };

    expect(result.exitCode).toBe(1);
    expect(output).toMatchObject({
      decision: "DENY",
      reason_code: "AMOUNT_EXCEEDS_PER_PAYMENT_MAX"
    });
  });

  it("runs init then check then verify-chain end to end", async () => {
    const workspace = await initializedWorkspace();
    const intentPath = join(workspace.root, "intent.json");
    writeFileSync(intentPath, `${JSON.stringify(validIntent)}\n`);

    const check = await run(["check", intentPath], workspace);
    const verify = await run(["verify-chain"], workspace);

    expect(workspace.init.exitCode).toBe(0);
    expect(check.exitCode).toBe(0);
    expect(verify.exitCode).toBe(0);
    expect(JSON.parse(verify.stdout)).toEqual({ valid: true });
  });

  it("verify exits 0 for a valid receipt and 1 for the same receipt with the wrong key", async () => {
    const workspace = await initializedWorkspace();
    const intentPath = join(workspace.root, "intent.json");
    writeFileSync(intentPath, `${JSON.stringify(validIntent)}\n`);
    const check = await run(["check", intentPath], workspace);
    const checkOutput = JSON.parse(check.stdout) as { receipt: unknown };
    const receiptPath = join(workspace.root, "receipt.json");
    writeFileSync(receiptPath, `${JSON.stringify(checkOutput.receipt)}\n`);

    const publicKey = readFileSync(join(configDir(workspace.configRoot), "ed25519.public.key"), "utf8").trim();
    const valid = await run(["verify", receiptPath, "--pubkey", publicKey], workspace);
    const invalid = await run(["verify", receiptPath, "--pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="], workspace);

    expect(valid.exitCode).toBe(0);
    expect(JSON.parse(valid.stdout)).toEqual({ valid: true });
    expect(invalid.exitCode).toBe(1);
    expect(JSON.parse(invalid.stdout)).toEqual({ valid: false });
  });

  it("export prints a portable receipt with the public key", async () => {
    const workspace = await initializedWorkspace();
    const intentPath = join(workspace.root, "intent.json");
    writeFileSync(intentPath, `${JSON.stringify(validIntent)}\n`);
    const check = await run(["check", intentPath], workspace);
    const checkOutput = JSON.parse(check.stdout) as { receipt: { receipt_id: string } };

    const exported = await run(["export", checkOutput.receipt.receipt_id], workspace);
    const portableReceipt = JSON.parse(exported.stdout) as { receipt_id: string; public_key: string };

    expect(exported.exitCode).toBe(0);
    expect(portableReceipt.receipt_id).toBe(checkOutput.receipt.receipt_id);
    expect(portableReceipt.public_key).toBe(
      readFileSync(join(configDir(workspace.configRoot), "ed25519.public.key"), "utf8").trim()
    );
  });
});
