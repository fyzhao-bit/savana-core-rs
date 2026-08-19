import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import type {
  HealthCheck,
  HealthFinding,
  OpenClawConfig,
} from "openclaw/plugin-sdk/health";

import type { DoctorSnapshot } from "./bridge-process.js";
import {
  BRIDGE_VERSION,
  OPENCLAW_VERSION,
  PROTOCOL_VERSION,
  type SavanaPluginConfig,
} from "./config.js";

export const SAVANA_DOCTOR_CHECK_ID = "savana.runtime";
const EXPECTED_ORIGINS = [
  "http://localhost:8768",
  "http://localhost:8767",
  "http://localhost:8766",
] as const;
const BRIDGE_CONFIG_KEYS = new Set([
  "version",
  "identity_path",
  "webauthn_fd",
  "release_journal_path",
  "release_canonical_host",
  "release_listen_port",
  "client_root_certificate_path",
  "server_certificate_path",
  "server_private_key_path",
  "expected_client_spki_pin_path",
  "max_steps",
  "max_replans",
  "turn_timeout_seconds",
  "approval_timeout_seconds",
  "release_delivery_timeout_seconds",
]);

export type SavanaDoctorProbe = () => Promise<DoctorSnapshot>;

export function createSavanaHealthCheck(
  pluginConfig: SavanaPluginConfig,
  probe: SavanaDoctorProbe,
): HealthCheck {
  return {
    id: SAVANA_DOCTOR_CHECK_ID,
    kind: "plugin",
    description: "Validate the fail-closed Savana runtime boundary",
    source: "@savana/openclaw-runtime",
    async detect(context) {
      return runSavanaDoctor(context.cfg, pluginConfig, probe);
    },
  };
}

export async function runSavanaDoctor(
  openClawConfig: OpenClawConfig,
  pluginConfig: SavanaPluginConfig,
  probe: SavanaDoctorProbe,
): Promise<readonly HealthFinding[]> {
  const findings: HealthFinding[] = [];
  const error = (requirement: string, message: string): void => {
    findings.push({
      checkId: SAVANA_DOCTOR_CHECK_ID,
      severity: "error",
      message,
      requirement,
    });
  };

  if (
    pluginConfig.protocolVersion !== PROTOCOL_VERSION ||
    pluginConfig.bridgeVersion !== BRIDGE_VERSION ||
    pluginConfig.openclawVersion !== OPENCLAW_VERSION
  ) {
    error("version-pin", "Savana runtime version pins do not match.");
  }
  checkOpenClawSelection(openClawConfig, error);

  let bridge: BridgeDeploymentConfig | undefined;
  try {
    await requireFile(pluginConfig.pythonExecutable, false);
    await requireFile(pluginConfig.bridgeConfigPath, true);
    bridge = await readBridgeConfig(pluginConfig.bridgeConfigPath);
    if (!limitsMatch(bridge, pluginConfig)) {
      error("limit-binding", "OpenClaw and Savana bridge limits do not match.");
    }
    await checkBridgeFiles(bridge);
    await checkCertificateBinding(bridge);
  } catch (failure) {
    const requirement =
      failure instanceof DoctorFailure ? failure.requirement : "private-files";
    error(requirement, "Savana bridge deployment files are not ready.");
  }

  try {
    const snapshot = await probe();
    if (
      snapshot.serviceOrigins.length !== EXPECTED_ORIGINS.length ||
      snapshot.serviceOrigins.some((origin, index) => origin !== EXPECTED_ORIGINS[index])
    ) {
      error("fixed-origins", "Savana SDK service origins are not the fixed loopback set.");
    }
    if (snapshot.activeConnectorCount < 1) {
      error("active-connectors", "No active signed Savana connector is available.");
    }
    if (bridge !== undefined && !validReleaseTarget(snapshot.releaseTargetUrl, bridge)) {
      error("release-target", "The live final-release target does not match deployment policy.");
    }
  } catch {
    error("live-probe", "Savana authenticated readiness probe failed.");
  }

  return findings;
}

type AddError = (requirement: string, message: string) => void;

function checkOpenClawSelection(config: OpenClawConfig, error: AddError): void {
  const plugin = config.plugins?.entries?.["savana"];
  if (
    config.plugins?.enabled === false ||
    plugin?.enabled === false ||
    config.plugins?.deny?.includes("savana") === true ||
    (config.plugins?.allow !== undefined && !config.plugins.allow.includes("savana"))
  ) {
    error("plugin-enabled", "The Savana plugin is not explicitly enabled.");
  }
  if (config.mcp !== undefined) {
    error("mcp-denied", "MCP must be disabled for the Savana personal assistant.");
  }

  const defaults = config.agents?.defaults;
  const agents = config.agents?.list ?? [];
  const selected = [defaults, ...agents].filter((agent) =>
    modelSelection(agent?.model).primary === "savana/agent",
  );
  if (!memoryDisabled(config, selected)) {
    error("memory-disabled", "OpenClaw memory must be disabled for the Savana agent.");
  }
  if (!boundedTranscriptRetention(config)) {
    error(
      "transcript-retention",
      "OpenClaw transcript retention must use the bounded Savana profile.",
    );
  }
  if (selected.length === 0) {
    error("model-selection", "No agent explicitly selects savana/agent.");
    return;
  }
  for (const agent of selected) {
    const selection = modelSelection(agent?.model);
    if (selection.fallbacks.length > 0) {
      error("no-fallback", "Savana agents must not configure model fallbacks.");
    }
    const model = agent?.models?.["savana/agent"] ?? defaults?.models?.["savana/agent"];
    if (model?.agentRuntime?.id !== "savana") {
      error("runtime-selection", "savana/agent must explicitly select the Savana harness.");
    }
    if (!toolsDenied((agent as { tools?: unknown } | undefined)?.tools)) {
      error("tools-denied", "OpenClaw tools must be denied for every Savana agent.");
    }
  }
}

function memoryDisabled(
  config: OpenClawConfig,
  agents: readonly unknown[],
): boolean {
  const plugins = config.plugins as
    | { slots?: { memory?: unknown } }
    | undefined;
  return (
    plugins?.slots?.memory === "none" &&
    agents.every((agent) => {
      if (agent === null || typeof agent !== "object" || Array.isArray(agent)) {
        return false;
      }
      const memorySearch = (agent as { memorySearch?: unknown }).memorySearch;
      return (
        memorySearch !== null &&
        typeof memorySearch === "object" &&
        !Array.isArray(memorySearch) &&
        (memorySearch as { enabled?: unknown }).enabled === false
      );
    })
  );
}

function boundedTranscriptRetention(config: OpenClawConfig): boolean {
  const session = (config as { session?: unknown }).session;
  if (session === null || typeof session !== "object" || Array.isArray(session)) {
    return false;
  }
  const maintenance = (session as { maintenance?: unknown }).maintenance;
  if (
    maintenance === null ||
    typeof maintenance !== "object" ||
    Array.isArray(maintenance)
  ) {
    return false;
  }
  const policy = maintenance as Record<string, unknown>;
  return (
    policy["mode"] === "enforce" &&
    durationAtMostSevenDays(policy["pruneAfter"]) &&
    durationAtMostSevenDays(policy["resetArchiveRetention"]) &&
    boundedPositiveInteger(policy["maxEntries"], 100) &&
    boundedPositiveInteger(policy["maxDiskBytes"], 64 * 1024 * 1024)
  );
}

function durationAtMostSevenDays(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const match = /^(\d+)d$/.exec(value);
  if (match === null) return false;
  const days = Number(match[1]);
  return Number.isSafeInteger(days) && days >= 1 && days <= 7;
}

function boundedPositiveInteger(value: unknown, maximum: number): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= maximum;
}

function modelSelection(value: unknown): { primary?: string; fallbacks: readonly string[] } {
  if (typeof value === "string") return { primary: value, fallbacks: [] };
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { fallbacks: [] };
  }
  const model = value as { primary?: unknown; fallbacks?: unknown };
  return {
    ...(typeof model.primary === "string" ? { primary: model.primary } : {}),
    fallbacks: Array.isArray(model.fallbacks)
      ? model.fallbacks.filter((item): item is string => typeof item === "string")
      : [],
  };
}

function toolsDenied(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const tools = value as Record<string, unknown>;
  const deny = tools["deny"];
  return (
    Array.isArray(deny) &&
    deny.length === 1 &&
    deny[0] === "*" &&
    !Object.hasOwn(tools, "allow") &&
    !Object.hasOwn(tools, "alsoAllow") &&
    !Object.hasOwn(tools, "byProvider") &&
    !Object.hasOwn(tools, "toolsBySender")
  );
}

interface BridgeDeploymentConfig {
  readonly version: 1;
  readonly identity_path: string;
  readonly webauthn_fd: 3;
  readonly release_journal_path: string;
  readonly release_canonical_host: string;
  readonly release_listen_port: number;
  readonly client_root_certificate_path: string;
  readonly server_certificate_path: string;
  readonly server_private_key_path: string;
  readonly expected_client_spki_pin_path: string;
  readonly max_steps: number;
  readonly max_replans: number;
  readonly turn_timeout_seconds: number;
  readonly approval_timeout_seconds: number;
  readonly release_delivery_timeout_seconds: number;
}

async function readBridgeConfig(configPath: string): Promise<BridgeDeploymentConfig> {
  const encoded = await readFile(configPath);
  if (encoded.length === 0 || encoded.length > 64 * 1024) {
    throw new DoctorFailure("bridge-config");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
  } catch {
    throw new DoctorFailure("bridge-config");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new DoctorFailure("bridge-config");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== BRIDGE_CONFIG_KEYS.size ||
    keys.some((key) => !BRIDGE_CONFIG_KEYS.has(key)) ||
    record["version"] !== 1 ||
    record["webauthn_fd"] !== 3
  ) {
    throw new DoctorFailure("bridge-config");
  }
  const paths = [
    "identity_path",
    "release_journal_path",
    "client_root_certificate_path",
    "server_certificate_path",
    "server_private_key_path",
    "expected_client_spki_pin_path",
  ];
  if (
    paths.some(
      (key) => typeof record[key] !== "string" || !path.isAbsolute(record[key] as string),
    ) ||
    typeof record["release_canonical_host"] !== "string" ||
    !Number.isInteger(record["release_listen_port"]) ||
    (record["release_listen_port"] as number) < 1 ||
    (record["release_listen_port"] as number) > 65535
  ) {
    throw new DoctorFailure("bridge-config");
  }
  const maxSteps = record["max_steps"];
  const maxReplans = record["max_replans"];
  const turnTimeout = record["turn_timeout_seconds"];
  const approvalTimeout = record["approval_timeout_seconds"];
  const releaseTimeout = record["release_delivery_timeout_seconds"];
  if (
    !Number.isInteger(maxSteps) ||
    (maxSteps as number) < 1 ||
    (maxSteps as number) > 64 ||
    !Number.isInteger(maxReplans) ||
    (maxReplans as number) < 1 ||
    (maxReplans as number) > 8 ||
    !boundedTimeout(turnTimeout, 300) ||
    (turnTimeout as number) < 1 ||
    !boundedTimeout(approvalTimeout, 300) ||
    !boundedTimeout(releaseTimeout, 60)
  ) {
    throw new DoctorFailure("bridge-config");
  }
  return record as unknown as BridgeDeploymentConfig;
}

function boundedTimeout(value: unknown, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0 &&
    value <= maximum
  );
}

function limitsMatch(
  bridge: BridgeDeploymentConfig,
  plugin: SavanaPluginConfig,
): boolean {
  return (
    bridge.max_steps === plugin.maxSteps &&
    bridge.max_replans === plugin.maxReplans &&
    bridge.turn_timeout_seconds === plugin.turnTimeoutSeconds &&
    bridge.approval_timeout_seconds === plugin.approvalTimeoutSeconds &&
    bridge.release_delivery_timeout_seconds ===
      plugin.releaseDeliveryTimeoutSeconds
  );
}

async function checkBridgeFiles(config: BridgeDeploymentConfig): Promise<void> {
  await requireFile(config.identity_path, true);
  await requireFile(config.client_root_certificate_path, false);
  await requireFile(config.server_certificate_path, false);
  await requireFile(config.server_private_key_path, true);
  await requireFile(config.expected_client_spki_pin_path, true);
  const journalParent = path.dirname(config.release_journal_path);
  const parent = await lstat(journalParent);
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    throw new DoctorFailure("release-journal");
  }
  const pin = await readFile(config.expected_client_spki_pin_path);
  if (pin.length !== 32 || pin.every((byte) => byte === 0)) {
    throw new DoctorFailure("client-pin");
  }
}

async function checkCertificateBinding(config: BridgeDeploymentConfig): Promise<void> {
  try {
    const ca = new X509Certificate(await readFile(config.client_root_certificate_path));
    const certificate = new X509Certificate(await readFile(config.server_certificate_path));
    if (
      certificate.checkHost(config.release_canonical_host) === undefined ||
      Date.parse(certificate.validFrom) > Date.now() ||
      Date.parse(certificate.validTo) <= Date.now() ||
      Date.parse(ca.validTo) <= Date.now()
    ) {
      throw new DoctorFailure("receiver-certificate");
    }
    const certificateKey = certificate.publicKey.export({ type: "spki", format: "der" });
    const privateKey = createPrivateKey({
      key: await readFile(config.server_private_key_path),
      format: "der",
      type: "pkcs8",
    });
    const privatePublicKey = createPublicKey(privateKey).export({
      type: "spki",
      format: "der",
    });
    if (
      certificateKey.length !== privatePublicKey.length ||
      !timingSafeEqual(certificateKey, privatePublicKey)
    ) {
      throw new DoctorFailure("receiver-key-binding");
    }
  } catch (failure) {
    if (failure instanceof DoctorFailure) throw failure;
    throw new DoctorFailure("receiver-certificate");
  }
}

async function requireFile(filePath: string, privateFile: boolean): Promise<void> {
  const metadata = await lstat(filePath);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0 ||
    (privateFile && process.platform !== "win32" && (metadata.mode & 0o077) !== 0)
  ) {
    throw new DoctorFailure("private-files");
  }
}

function validReleaseTarget(url: string, config: BridgeDeploymentConfig): boolean {
  try {
    const target = new URL(url);
    return (
      target.protocol === "https:" &&
      target.hostname === config.release_canonical_host &&
      target.port === String(config.release_listen_port) &&
      target.pathname === "/savana/final-release" &&
      target.username === "" &&
      target.password === "" &&
      target.search === "" &&
      target.hash === ""
    );
  } catch {
    return false;
  }
}

class DoctorFailure extends Error {
  constructor(readonly requirement: string) {
    super("Savana doctor check failed");
  }
}
