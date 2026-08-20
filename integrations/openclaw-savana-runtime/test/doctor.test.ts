import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate, createHash } from "node:crypto";

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
    execd: path.join(directory, "execd-bootstrap-v2.json"),
    identity: path.join(directory, "identity.cbor"),
    journal: path.join(directory, "release.cbor"),
    ca: path.join(directory, "ca.der"),
    certificate: path.join(directory, "server.der"),
    key: path.join(directory, "server.key"),
    pin: path.join(directory, "client.pin"),
    clientCertificate: path.join(directory, "client.der"),
    clientIntermediate: path.join(directory, "client-intermediate.der"),
  };
  await writeFile(files.python, "#!/bin/false\n", { mode: 0o700 });
  await writeFile(files.identity, Buffer.alloc(32, 1), { mode: 0o600 });
  await writeFile(files.ca, fixture["ca_cert"] ?? Buffer.alloc(0), { mode: 0o600 });
  await writeFile(files.certificate, fixture["server_cert"] ?? Buffer.alloc(0), {
    mode: 0o600,
  });
  await writeFile(files.key, fixture["server_key"] ?? Buffer.alloc(0), { mode: 0o600 });
  await writeFile(files.clientCertificate, fixture["client_cert"] ?? Buffer.alloc(0), {
    mode: 0o600,
  });
  await writeFile(files.clientIntermediate, fixture["ca_cert"] ?? Buffer.alloc(0), {
    mode: 0o600,
  });
  const serverSpki = new X509Certificate(fixture["server_cert"] ?? Buffer.alloc(0))
    .publicKey.export({ type: "spki", format: "der" });
  const clientSpki = new X509Certificate(fixture["client_cert"] ?? Buffer.alloc(0))
    .publicKey.export({ type: "spki", format: "der" });
  const rootDigest = createHash("sha256").update(fixture["ca_cert"] ?? Buffer.alloc(0)).digest();
  const clientDigest = createHash("sha256")
    .update(fixture["client_cert"] ?? Buffer.alloc(0))
    .digest();
  await writeFile(files.pin, createHash("sha256").update(clientSpki).digest(), {
    mode: 0o600,
  });
  const endpoint = createHash("sha256");
  endpoint.update(Buffer.from("SAVANA_PROVIDER_TLS_ENDPOINT_BINDING_V2\0"));
  endpoint.update(Buffer.from([4, 127, 0, 0, 1]));
  const port = Buffer.alloc(2);
  port.writeUInt16BE(43191);
  endpoint.update(port);
  const host = Buffer.from("provider.example");
  const hostLength = Buffer.alloc(2);
  hostLength.writeUInt16BE(host.length);
  endpoint.update(hostLength);
  endpoint.update(host);
  endpoint.update(rootDigest);
  endpoint.update(clientDigest);
  const alpn = Buffer.from("savana-provider-v2");
  const alpnLength = Buffer.alloc(2);
  alpnLength.writeUInt16BE(alpn.length);
  endpoint.update(alpnLength);
  endpoint.update(alpn);
  const credential = createHash("sha256");
  credential.update(Buffer.from("SAVANA_PROVIDER_CREDENTIAL_HANDLE_IDENTITY_V2\0"));
  credential.update(clientDigest);
  await writeFile(
    files.execd,
    JSON.stringify({
      provider_routing_mode: "split-final-release",
      final_release_provider: {
        address: "127.0.0.1:43191",
        server_name: "provider.example",
        canonical_url: "https://provider.example:43191/savana/final-release",
        server_spki_sha256: createHash("sha256").update(serverSpki).digest("hex"),
        root_certificate_path: files.ca,
        root_certificate_digest: rootDigest.toString("hex"),
        client_certificate_paths: [files.clientCertificate, files.clientIntermediate],
        client_certificate_digests: [
          clientDigest.toString("hex"),
          rootDigest.toString("hex"),
        ],
        alpn_protocol_hex: alpn.toString("hex"),
        endpoint_binding_digest: endpoint.digest("hex"),
        credential_handle_identity_digest: credential.digest("hex"),
      },
    }),
    { mode: 0o600 },
  );
  await writeFile(
    files.bridge,
    JSON.stringify({
      version: 1,
      identity_path: files.identity,
      execd_bootstrap_path: files.execd,
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
      slots: { memory: "none" },
      entries: { savana: { enabled: true, config: { ...plugin } } },
    },
    agents: {
      list: [
        {
          id: "personal",
          model: { primary: "savana/agent" },
          models: { "savana/agent": { agentRuntime: { id: "savana" } } },
          memorySearch: { enabled: false },
          tools: { deny: ["*"] },
        },
      ],
    },
    session: {
      maintenance: {
        mode: "enforce",
        pruneAfter: "7d",
        maxEntries: 100,
        resetArchiveRetention: "7d",
        maxDiskBytes: 64 * 1024 * 1024,
      },
    },
  } satisfies OpenClawConfig;
  return {
    config,
    files,
    plugin,
    doctorDependencies: { rootOwned: async (candidate: string) => candidate === files.execd },
  };
}

describe("Savana OpenClaw doctor", () => {
  it("accepts a private pinned deployment with a live signed connector", async () => {
    const { config, plugin, doctorDependencies } = await deployment();
    const findings = await runSavanaDoctor(config, plugin, async () => ({
      activeConnectorCount: 1,
      releaseTargetUrl: "https://provider.example:43191/savana/final-release",
      serviceOrigins: [
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
      ],
    }), doctorDependencies);
    expect(findings).toEqual([]);
  });

  it("fails closed without printing paths, pins, or private configuration", async () => {
    const { config, files, plugin, doctorDependencies } = await deployment();
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
    }), doctorDependencies);
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
    const { config, plugin, doctorDependencies } = await deployment();
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
      doctorDependencies,
    );
    expect(findings.map((finding) => finding.requirement)).toContain(
      "limit-binding",
    );
  });

  it("rejects unbounded OpenClaw memory and transcript retention", async () => {
    const { config, plugin, doctorDependencies } = await deployment();
    const unsafe = {
      ...config,
      plugins: { ...config.plugins, slots: { memory: "memory-core" } },
      agents: {
        list: config.agents.list.map((agent) => ({
          ...agent,
          memorySearch: { enabled: true },
        })),
      },
      session: { maintenance: { mode: "warn", pruneAfter: "30d" } },
    } as unknown as OpenClawConfig;
    const findings = await runSavanaDoctor(unsafe, plugin, async () => ({
      activeConnectorCount: 1,
      releaseTargetUrl: "https://provider.example:43191/savana/final-release",
      serviceOrigins: [
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
      ],
    }), doctorDependencies);
    expect(findings.map((finding) => finding.requirement)).toEqual(
      expect.arrayContaining(["memory-disabled", "transcript-retention"]),
    );
  });
});
