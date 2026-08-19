import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { OpenClawConfig } from "openclaw/plugin-sdk/health";
import { describe, expect, it } from "vitest";

import type { SavanaPluginConfig } from "../src/config.js";
import { runSavanaDoctor } from "../src/doctor.js";

const REPOSITORY = path.resolve(import.meta.dirname, "../../..");
const TLS_FIXTURE = path.join(
  REPOSITORY,
  "crates/savana-execd/tests/fixtures/provider-tls-v2.hex",
);

async function deployment() {
  const directory = await mkdtemp(path.join(tmpdir(), "savana-doctor-"));
  const fixture = Object.fromEntries(
    (await readFile(TLS_FIXTURE, "utf8"))
      .trim()
      .split("\n")
      .map((line) => {
        const [name, encoded] = line.split("=", 2);
        return [name, Buffer.from(encoded ?? "", "hex")];
      }),
  ) as Record<string, Buffer>;
  const files = {
    python: path.join(directory, "python3"),
    bridge: path.join(directory, "bridge.json"),
    identity: path.join(directory, "identity.cbor"),
    journal: path.join(directory, "release.cbor"),
    ca: path.join(directory, "ca.der"),
    certificate: path.join(directory, "server.der"),
    key: path.join(directory, "server.key"),
    pin: path.join(directory, "client.pin"),
  };
  await writeFile(files.python, "#!/bin/false\n", { mode: 0o700 });
  await writeFile(files.identity, Buffer.alloc(32, 1), { mode: 0o600 });
  await writeFile(files.ca, fixture["ca_cert"] ?? Buffer.alloc(0), { mode: 0o600 });
  await writeFile(files.certificate, fixture["server_cert"] ?? Buffer.alloc(0), {
    mode: 0o600,
  });
  await writeFile(files.key, fixture["server_key"] ?? Buffer.alloc(0), { mode: 0o600 });
  await writeFile(files.pin, Buffer.alloc(32, 2), { mode: 0o600 });
  await writeFile(
    files.bridge,
    JSON.stringify({
      version: 1,
      identity_path: files.identity,
      webauthn_fd: 3,
      release_journal_path: files.journal,
      release_canonical_host: "provider.example",
      release_listen_port: 43191,
      client_root_certificate_path: files.ca,
      server_certificate_path: files.certificate,
      server_private_key_path: files.key,
      expected_client_spki_pin_path: files.pin,
      max_steps: 24,
      max_replans: 4,
      turn_timeout_seconds: 120,
      approval_timeout_seconds: 120,
      release_delivery_timeout_seconds: 30,
    }),
    { mode: 0o600 },
  );
  const plugin: SavanaPluginConfig = {
    pythonExecutable: files.python,
    bridgeConfigPath: files.bridge,
    protocolVersion: 1,
    bridgeVersion: "0.1.0",
    openclawVersion: "2026.7.1-2",
    maxSteps: 24,
    maxReplans: 4,
    turnTimeoutSeconds: 120,
    approvalTimeoutSeconds: 120,
    releaseDeliveryTimeoutSeconds: 30,
    logLevel: "warn",
  };
  const config = {
    plugins: {
      enabled: true,
      allow: ["savana"],
      entries: { savana: { enabled: true, config: { ...plugin } } },
    },
    agents: {
      list: [
        {
          id: "personal",
          model: { primary: "savana/agent" },
          models: { "savana/agent": { agentRuntime: { id: "savana" } } },
          tools: { deny: ["*"] },
        },
      ],
    },
  } satisfies OpenClawConfig;
  return { config, files, plugin };
}

describe("Savana OpenClaw doctor", () => {
  it("accepts a private pinned deployment with a live signed connector", async () => {
    const { config, plugin } = await deployment();
    const findings = await runSavanaDoctor(config, plugin, async () => ({
      activeConnectorCount: 1,
      releaseTargetUrl: "https://provider.example:43191/savana/final-release",
      serviceOrigins: [
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
      ],
    }));
    expect(findings).toEqual([]);
  });

  it("fails closed without printing paths, pins, or private configuration", async () => {
    const { config, files, plugin } = await deployment();
    await chmod(files.bridge, 0o644);
    const unsafe = {
      ...config,
      mcp: { servers: {} },
      agents: {
        list: [
          {
            id: "personal",
            model: { primary: "savana/agent", fallbacks: ["openai/gpt-5"] },
            models: { "savana/agent": { agentRuntime: { id: "openclaw" } } },
            tools: { allow: ["mcp"], deny: ["*"] },
          },
        ],
      },
    } as unknown as OpenClawConfig;
    const findings = await runSavanaDoctor(unsafe, plugin, async () => ({
      activeConnectorCount: 0,
      releaseTargetUrl: "http://remote.example/release",
      serviceOrigins: ["https://remote.example", "x", "y"],
    }));
    const requirements = findings.map((finding) => finding.requirement);
    expect(requirements).toEqual(
      expect.arrayContaining([
        "mcp-denied",
        "no-fallback",
        "runtime-selection",
        "tools-denied",
        "private-files",
        "fixed-origins",
        "active-connectors",
      ]),
    );
    const rendered = JSON.stringify(findings);
    expect(rendered).not.toContain(files.bridge);
    expect(rendered).not.toContain("openai/gpt-5");
  });

  it("rejects plugin limits that differ from the private bridge limits", async () => {
    const { config, plugin } = await deployment();
    const findings = await runSavanaDoctor(
      config,
      { ...plugin, releaseDeliveryTimeoutSeconds: 31 },
      async () => ({
        activeConnectorCount: 1,
        releaseTargetUrl: "https://provider.example:43191/savana/final-release",
        serviceOrigins: [
          "http://localhost:8768",
          "http://localhost:8767",
          "http://localhost:8766",
        ],
      }),
    );
    expect(findings.map((finding) => finding.requirement)).toContain(
      "limit-binding",
    );
  });
});
