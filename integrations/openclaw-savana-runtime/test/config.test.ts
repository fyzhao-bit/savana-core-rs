import { describe, expect, it } from "vitest";

import {
  BRIDGE_VERSION,
  OPENCLAW_VERSION,
  PROTOCOL_VERSION,
  parsePluginConfig,
} from "../src/config.js";

function validConfig(): Record<string, unknown> {
  return {
    pythonExecutable: "/usr/bin/python3",
    bridgeConfigPath: "/var/lib/savana/openclaw-bridge.json",
    bridgeWorkingDirectory: "/var/lib/savana",
    protocolVersion: PROTOCOL_VERSION,
    bridgeVersion: BRIDGE_VERSION,
    openclawVersion: OPENCLAW_VERSION,
    maxSteps: 24,
    maxReplans: 4,
    turnTimeoutSeconds: 120,
    approvalTimeoutSeconds: 120,
    releaseDeliveryTimeoutSeconds: 30,
    logLevel: "warn",
  };
}

describe("parsePluginConfig", () => {
  it("accepts only the pinned, bounded production schema", () => {
    expect(parsePluginConfig(validConfig())).toEqual(validConfig());
  });

  it.each([
    ["unknown key", { ...validConfig(), bootstrapToken: "secret" }],
    ["relative Python", { ...validConfig(), pythonExecutable: "python3" }],
    ["relative config", { ...validConfig(), bridgeConfigPath: "bridge.json" }],
    ["OpenClaw drift", { ...validConfig(), openclawVersion: "2026.7.2" }],
    ["bridge drift", { ...validConfig(), bridgeVersion: "0.2.0" }],
    ["protocol drift", { ...validConfig(), protocolVersion: 2 }],
    ["too many steps", { ...validConfig(), maxSteps: 65 }],
    ["too many replans", { ...validConfig(), maxReplans: 9 }],
    ["unbounded turn", { ...validConfig(), turnTimeoutSeconds: 301 }],
    ["unbounded approval", { ...validConfig(), approvalTimeoutSeconds: 301 }],
    ["unbounded delivery", { ...validConfig(), releaseDeliveryTimeoutSeconds: 61 }],
    ["secret-shaped config", { ...validConfig(), apiKey: "sk-inline-secret" }],
  ])("rejects %s", (_name, value) => {
    expect(() => parsePluginConfig(value)).toThrow("invalid Savana plugin configuration");
  });
});
