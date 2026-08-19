import path from "node:path";

export const PROTOCOL_VERSION = 1 as const;
export const BRIDGE_VERSION = "0.1.0" as const;
export const OPENCLAW_VERSION = "2026.7.1-2" as const;

const CONFIG_KEYS = new Set([
  "pythonExecutable",
  "bridgeConfigPath",
  "bridgeWorkingDirectory",
  "protocolVersion",
  "bridgeVersion",
  "openclawVersion",
  "maxSteps",
  "maxReplans",
  "turnTimeoutSeconds",
  "approvalTimeoutSeconds",
  "releaseDeliveryTimeoutSeconds",
  "logLevel",
]);
const REQUIRED_KEYS = new Set(
  [...CONFIG_KEYS].filter((key) => key !== "bridgeWorkingDirectory"),
);

export type PluginLogLevel = "error" | "warn" | "info";

export interface SavanaPluginConfig {
  readonly pythonExecutable: string;
  readonly bridgeConfigPath: string;
  readonly bridgeWorkingDirectory?: string;
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly bridgeVersion: typeof BRIDGE_VERSION;
  readonly openclawVersion: typeof OPENCLAW_VERSION;
  readonly maxSteps: number;
  readonly maxReplans: number;
  readonly turnTimeoutSeconds: number;
  readonly approvalTimeoutSeconds: number;
  readonly releaseDeliveryTimeoutSeconds: number;
  readonly logLevel: PluginLogLevel;
}

export class ConfigError extends Error {
  constructor() {
    super("invalid Savana plugin configuration");
    this.name = "ConfigError";
  }
}

export function parsePluginConfig(value: unknown): SavanaPluginConfig {
  const record = asRecord(value);
  const keys = Object.keys(record);
  if (
    keys.some((key) => !CONFIG_KEYS.has(key)) ||
    [...REQUIRED_KEYS].some((key) => !Object.hasOwn(record, key))
  ) {
    throw new ConfigError();
  }

  const pythonExecutable = absolutePath(record["pythonExecutable"]);
  const bridgeConfigPath = absolutePath(record["bridgeConfigPath"]);
  const bridgeWorkingDirectory = Object.hasOwn(record, "bridgeWorkingDirectory")
    ? absolutePath(record["bridgeWorkingDirectory"])
    : undefined;
  if (
    record["protocolVersion"] !== PROTOCOL_VERSION ||
    record["bridgeVersion"] !== BRIDGE_VERSION ||
    record["openclawVersion"] !== OPENCLAW_VERSION
  ) {
    throw new ConfigError();
  }

  const maxSteps = boundedInteger(record["maxSteps"], 1, 64);
  const maxReplans = boundedInteger(record["maxReplans"], 1, 8);
  const turnTimeoutSeconds = boundedNumber(record["turnTimeoutSeconds"], 300);
  const approvalTimeoutSeconds = boundedNumber(
    record["approvalTimeoutSeconds"],
    300,
  );
  const releaseDeliveryTimeoutSeconds = boundedNumber(
    record["releaseDeliveryTimeoutSeconds"],
    60,
  );
  const logLevel = record["logLevel"];
  if (logLevel !== "error" && logLevel !== "warn" && logLevel !== "info") {
    throw new ConfigError();
  }

  return Object.freeze({
    pythonExecutable,
    bridgeConfigPath,
    ...(bridgeWorkingDirectory === undefined ? {} : { bridgeWorkingDirectory }),
    protocolVersion: PROTOCOL_VERSION,
    bridgeVersion: BRIDGE_VERSION,
    openclawVersion: OPENCLAW_VERSION,
    maxSteps,
    maxReplans,
    turnTimeoutSeconds,
    approvalTimeoutSeconds,
    releaseDeliveryTimeoutSeconds,
    logLevel,
  });
}

function asRecord(value: unknown): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new ConfigError();
  }
  return value as Record<string, unknown>;
}

function absolutePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    Buffer.byteLength(value, "utf8") > 4096 ||
    !path.isAbsolute(value)
  ) {
    throw new ConfigError();
  }
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ConfigError();
  }
  return value as number;
}

function boundedNumber(value: unknown, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value <= 0 ||
    value > maximum
  ) {
    throw new ConfigError();
  }
  return value;
}
