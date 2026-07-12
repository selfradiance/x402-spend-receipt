export function isCaip2Network(value: string): boolean {
  return /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/u.test(value);
}

export function mapFactsNetwork(network: string): string | null {
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

export function normalizeTransactionHash(value: string): string | null {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value)) {
    return null;
  }

  return value.toLowerCase();
}
