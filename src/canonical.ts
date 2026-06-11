import { createHash } from "node:crypto";

type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function assertJsonValue(value: unknown): JsonValue {
  if (value === null) {
    return null;
  }

  if (Array.isArray(value)) {
    return value.map((item) => assertJsonValue(item));
  }

  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("JSON value does not support non-finite numbers");
      }
      return value;
    case "object": {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("JSON value only supports plain objects");
      }

      const result: { [key: string]: JsonValue } = {};
      for (const [key, fieldValue] of Object.entries(value)) {
        result[key] = assertJsonValue(fieldValue);
      }
      return result;
    }
    default:
      throw new TypeError(`JSON value does not support ${typeof value}`);
  }
}

export function canonicalJson(value: JsonValue): string {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("Canonical JSON does not support non-finite numbers");
      }
      return JSON.stringify(value);
    case "object": {
      const entries = Object.entries(value).sort(([left], [right]) => {
        if (left < right) {
          return -1;
        }
        if (left > right) {
          return 1;
        }
        return 0;
      });
      const fields = entries.map(([key, fieldValue]) => `${JSON.stringify(key)}:${canonicalJson(fieldValue)}`);
      return `{${fields.join(",")}}`;
    }
    default:
      throw new TypeError(`Canonical JSON does not support ${typeof value}`);
  }
}

export function canonicalJsonBytes(value: JsonValue): Uint8Array {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function canonicalSha256Hex(value: JsonValue): string {
  return sha256Hex(canonicalJsonBytes(value));
}
