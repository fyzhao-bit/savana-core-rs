import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import { describe, expect, it, vi } from "vitest";

import { parsePluginConfig } from "../src/config.js";
import {
  BridgeFailure,
  BridgeProcess,
  type ChildProcessLike,
  type SpawnBridge,
} from "../src/bridge-process.js";

function config() {
  return parsePluginConfig({
    pythonExecutable: "/opt/savana/bin/python3",
    bridgeConfigPath: "/var/lib/savana/bridge.json",
    bridgeWorkingDirectory: "/var/lib/savana",
    protocolVersion: 1,
    bridgeVersion: "0.1.0",
    openclawVersion: "2026.7.1-2",
    maxSteps: 24,
    maxReplans: 4,
    turnTimeoutSeconds: 120,
    approvalTimeoutSeconds: 120,
    releaseDeliveryTimeoutSeconds: 30,
    logLevel: "warn",
  });
}

class FakeChild extends EventEmitter implements ChildProcessLike {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly kill = vi.fn(() => true);
  written = "";

  constructor() {
    super();
    this.stdin.on("data", (chunk: Buffer) => {
      this.written += chunk.toString("utf8");
    });
  }

  reply(message: Record<string, unknown>): void {
    this.stdout.write(`${JSON.stringify(message)}\n`);
  }

  crash(): void {
    this.emit("exit", 9, null);
  }
}

function fixture(parentEnvironment: NodeJS.ProcessEnv = {}) {
  const child = new FakeChild();
  const calls: unknown[][] = [];
  const spawn: SpawnBridge = (command, arguments_, options) => {
    calls.push([command, arguments_, options]);
    return child;
  };
  const diagnostics: string[] = [];
  const bridge = new BridgeProcess(config(), {
    spawn,
    parentEnvironment,
    diagnostic: (code) => diagnostics.push(code),
  });
  return { bridge, calls, child, diagnostics };
}

async function initialize(bridge: BridgeProcess, child: FakeChild): Promise<void> {
  const started = bridge.start();
  await vi.waitFor(() => expect(child.written).toContain('"type":"initialize"'));
  child.reply({
    bridge_version: "0.1.0",
    protocol_version: 1,
    request_id: 1,
    type: "initialized",
  });
  await started;
}

describe("BridgeProcess", () => {
  it("spawns the absolute Python module without a shell or inherited secrets", async () => {
    const { bridge, calls, child } = fixture({
      LANG: "en_US.UTF-8",
      LC_ALL: "C.UTF-8",
      TZ: "UTC",
      HOME: "/secret/home",
      PATH: "/secret/bin",
      API_TOKEN: "secret",
    });
    await initialize(bridge, child);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual([
      "/opt/savana/bin/python3",
      ["-m", "savana.openclaw_bridge", "--config", "/var/lib/savana/bridge.json"],
      {
        cwd: "/var/lib/savana",
        env: {
          LANG: "en_US.UTF-8",
          LC_ALL: "C.UTF-8",
          TZ: "UTC",
          PYTHONNOUSERSITE: "1",
          PYTHONDONTWRITEBYTECODE: "1",
          PYTHONUNBUFFERED: "1",
        },
        shell: false,
        stdio: ["pipe", "pipe", "pipe", 3],
      },
    ]);
    await bridge.dispose();
  });

  it("uses the non-listening bridge mode for doctor probes", async () => {
    const child = new FakeChild();
    const calls: unknown[][] = [];
    const bridge = new BridgeProcess(config(), {
      doctorOnly: true,
      spawn: (command, arguments_, options) => {
        calls.push([command, arguments_, options]);
        return child;
      },
    });
    await initialize(bridge, child);
    expect(calls[0]?.[1]).toEqual([
      "-m",
      "savana.openclaw_bridge",
      "--doctor-config",
      "/var/lib/savana/bridge.json",
    ]);
    await bridge.dispose();
  });

  it("correlates progress, approval, abort, and exactly one terminal", async () => {
    const { bridge, child } = fixture();
    await initialize(bridge, child);
    const events: string[] = [];
    const approvals: string[] = [];
    const abort = new AbortController();
    const turn = bridge.runTurn({
      agentId: "agent",
      sessionId: "opaque-session",
      turnId: "turn",
      text: "private request",
      signal: abort.signal,
      onEvent: (event) => {
        events.push(event.event);
      },
      onApproval: async (request) => {
        approvals.push(request.display);
        return true;
      },
    });

    child.reply({
      protocol_version: 1,
      request_id: 2,
      type: "turn.event",
      event: "planning",
    });
    child.reply({
      protocol_version: 1,
      request_id: 2,
      type: "approval.request",
      approval_id: "approval",
      display: "Approve exact effect",
      purpose: "tool_execution",
      deadline_unix_ms: Date.now() + 30_000,
    });
    await vi.waitFor(() => expect(approvals).toEqual(["Approve exact effect"]));
    await vi.waitFor(() =>
      expect(child.written).toContain('"type":"approval.answer"'),
    );
    abort.abort();
    child.reply({
      protocol_version: 1,
      request_id: 2,
      type: "turn.failed",
      code: "cancelled",
    });

    await expect(turn).rejects.toMatchObject({ code: "cancelled" });
    expect(events).toEqual(["planning"]);
    const written = child.written;
    expect(written).toContain('"type":"approval.answer"');
    expect(written).toContain('"approved":true');
    expect(written).toContain('"type":"turn.cancel"');
    expect(written).not.toContain("Approve exact effect");
    await bridge.dispose();
  });

  it("returns only the closed public doctor snapshot", async () => {
    const { bridge, child } = fixture();
    await initialize(bridge, child);
    const doctor = bridge.doctor();
    await vi.waitFor(() => expect(child.written).toContain('"type":"doctor.request"'));
    child.reply({
      protocol_version: 1,
      request_id: 2,
      type: "doctor.result",
      active_connector_count: 1,
      release_target_url: "https://provider.example:43191/savana/final-release",
      service_origins: [
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
      ],
    });
    await expect(doctor).resolves.toEqual({
      activeConnectorCount: 1,
      releaseTargetUrl: "https://provider.example:43191/savana/final-release",
      serviceOrigins: [
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
      ],
    });
    await bridge.dispose();
  });

  it("fails closed on crash, duplicate terminal, oversized output, and redacts stderr", async () => {
    const { bridge, child, diagnostics } = fixture();
    await initialize(bridge, child);
    const turn = bridge.runTurn({
      agentId: "agent",
      sessionId: "opaque-session",
      turnId: "turn",
      text: "request",
      onEvent: () => undefined,
      onApproval: async () => false,
    });
    child.stderr.write("raw secret must not be logged\n");
    child.crash();
    await expect(turn).rejects.toMatchObject({ code: "indeterminate" });
    expect(diagnostics).toEqual(["bridge_stderr", "bridge_exit"]);
    await expect(
      bridge.runTurn({
        agentId: "agent",
        sessionId: "opaque-session",
        turnId: "next",
        text: "must not replay",
        onEvent: () => undefined,
        onApproval: async () => false,
      }),
    ).rejects.toBeInstanceOf(BridgeFailure);
  });

  it("poisons the process when a completed request receives another terminal", async () => {
    const { bridge, child } = fixture();
    await initialize(bridge, child);
    const turn = bridge.runTurn({
      agentId: "agent",
      sessionId: "opaque-session",
      turnId: "turn",
      text: "request",
      onEvent: () => undefined,
      onApproval: async () => false,
    });
    const terminal = {
      protocol_version: 1,
      request_id: 2,
      type: "turn.released",
      text: "released",
    } as const;
    child.reply(terminal);
    await expect(turn).resolves.toEqual({ text: "released" });
    child.reply(terminal);
    await vi.waitFor(() => expect(bridge.closed).toBe(true));
    expect(child.kill).toHaveBeenCalledOnce();
  });
});
