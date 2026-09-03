import type { AgentHarnessAttemptParams } from "openclaw/plugin-sdk/agent-harness-runtime";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { describe, expect, it, vi } from "vitest";

import plugin from "../index.js";
import type { ReleasedTurn, RunTurnOptions } from "../src/bridge-process.js";
import { BridgeFailure } from "../src/bridge-process.js";
import { createSavanaHarness } from "../src/harness.js";
import { savanaProvider } from "../src/provider.js";

class FakeBridge {
  readonly start = vi.fn(async () => undefined);
  readonly reset = vi.fn(async () => undefined);
  readonly dispose = vi.fn(async () => undefined);
  readonly calls: RunTurnOptions[] = [];
  hold: Promise<void> | undefined;
  failure: BridgeFailure | undefined;

  async runTurn(options: RunTurnOptions): Promise<ReleasedTurn> {
    this.calls.push(options);
    await options.onEvent({ event: "planning" });
    await options.onEvent({
      event: "approval_required",
      purpose: "tool_execution",
    });
    if (this.failure !== undefined) throw this.failure;
    await this.hold;
    return { text: "released response" };
  }
}

function params(overrides: Record<string, unknown> = {}): AgentHarnessAttemptParams {
  return {
    provider: "savana",
    modelId: "agent",
    agentHarnessId: "savana",
    sessionId: "openclaw-session",
    sessionKey: "agent:main:session",
    sessionFile: "/private/session.jsonl",
    agentId: "personal",
    runId: "run",
    trigger: "user",
    currentInboundEventKind: "user_request",
    transcriptPrompt: "current user request",
    currentInboundContext: { text: "current user request" },
    prompt: "SYSTEM SECRET + MEMORY + current user request",
    images: [],
    imageOrder: [],
    clientTools: [],
    toolsAllow: [],
    model: { api: "openai-responses" },
    ...overrides,
  } as unknown as AgentHarnessAttemptParams;
}

function runtime() {
  const bridge = new FakeBridge();
  let activeHandle:
    | {
        queueMessage(text: string): Promise<void>;
      }
    | undefined;
  const events: unknown[] = [];
  const harness = createSavanaHarness(bridge, {
    activate: (_sessionId, handle) => {
      activeHandle = handle;
    },
    deactivate: () => {
      activeHandle = undefined;
    },
  });
  return {
    active: () => activeHandle,
    bridge,
    events,
    harness,
  };
}

describe("Savana harness", () => {
  it("supports only explicit savana/agent runtime selection", () => {
    const { harness } = runtime();
    expect(
      harness.supports({
        provider: "savana",
        modelId: "agent",
        requestedRuntime: "savana",
      }),
    ).toEqual({ supported: true, priority: 100 });
    for (const value of [
      { provider: "savana", modelId: "agent", requestedRuntime: "auto" },
      { provider: "savana", modelId: "other", requestedRuntime: "savana" },
      { provider: "openai", modelId: "agent", requestedRuntime: "savana" },
    ]) {
      expect(harness.supports(value)).toMatchObject({ supported: false });
    }
  });

  it("sends only current inbound text and emits only released assistant bytes", async () => {
    const { active, bridge, harness } = runtime();
    let resume: () => void = () => undefined;
    bridge.hold = new Promise<void>((resolve) => {
      resume = resolve;
    });
    const agentEvents: unknown[] = [];
    const attempt = harness.runAttempt(
      params({
        onAgentEvent: (event: unknown) => {
          agentEvents.push(event);
        },
      }),
    );
    await vi.waitFor(() => expect(bridge.calls).toHaveLength(1));
    await expect(active()?.queueMessage("Approve")).rejects.toThrow(
      "trusted product UI",
    );
    resume();
    const result = await attempt;

    expect(bridge.calls[0]?.text).toBe("current user request");
    expect(JSON.stringify(bridge.calls[0])).not.toContain("SYSTEM SECRET");
    expect(result.assistantTexts).toEqual(["released response"]);
    expect(result.lastAssistant?.content).toEqual([
      { type: "text", text: "released response" },
    ]);
    expect(result.replayMetadata).toEqual({
      hadPotentialSideEffects: true,
      replaySafe: false,
    });
    expect(agentEvents).toEqual([
      {
        stream: "savana.lifecycle",
        data: { event: "planning" },
        sessionKey: "agent:main:session",
      },
      {
        stream: "savana.lifecycle",
        data: { event: "approval_required", purpose: "tool_execution" },
        sessionKey: "agent:main:session",
      },
    ]);
  });

  it("retires an indeterminate binding and never falls back or replays", async () => {
    const { bridge, harness } = runtime();
    bridge.failure = new BridgeFailure("indeterminate");
    await expect(harness.runAttempt(params())).rejects.toMatchObject({
      code: "indeterminate",
    });
    const firstBinding = bridge.calls[0]?.sessionId;
    await expect(harness.runAttempt(params({ runId: "run-2" }))).rejects.toMatchObject({
      code: "indeterminate",
    });
    expect(bridge.calls[1]?.sessionId).not.toBe(firstBinding);
    expect(bridge.calls).toHaveLength(2);
  });

  it("resets and disposes native bridge sessions", async () => {
    const { bridge, harness } = runtime();
    await expect(harness.runAttempt(params())).resolves.toMatchObject({
      assistantTexts: ["released response"],
    });

    await harness.reset?.({
      agentId: "personal",
      sessionId: "openclaw-session",
    });
    await harness.dispose?.();
    expect(bridge.dispose).toHaveBeenCalledOnce();
  });
});

describe("provider and plugin registration", () => {
  it("pins a synthetic loopback-only savana/agent model", async () => {
    expect(savanaProvider.id).toBe("savana");
    expect(savanaProvider.resolveSyntheticAuth?.({ provider: "savana" })).toEqual({
      apiKey: "savana-native-runtime",
      source: "savana-native-runtime",
      mode: "token",
    });
    const catalog = await savanaProvider.staticCatalog?.run({} as never);
    expect(catalog).toMatchObject({
      provider: {
        baseUrl: "http://127.0.0.1:1",
        models: [
          {
            id: "agent",
            input: ["text"],
            agentRuntime: { id: "savana" },
          },
        ],
      },
    });
  });

  it("registers one provider and one harness, with no tools or MCP", () => {
    const providers: unknown[] = [];
    const harnesses: unknown[] = [];
    const registerTool = vi.fn();
    const registerCli = vi.fn();
    plugin.register?.({
      pluginConfig: {
        pythonExecutable: "/opt/savana/bin/python3",
        bridgeConfigPath: "/var/lib/savana/bridge.json",
        protocolVersion: 1,
        bridgeVersion: "0.1.0",
        openclawVersion: "2026.7.1-2",
        maxSteps: 24,
        maxReplans: 4,
        turnTimeoutSeconds: 120,
        approvalTimeoutSeconds: 120,
        releaseDeliveryTimeoutSeconds: 30,
        logLevel: "warn",
      },
      registerProvider: (provider: unknown) => providers.push(provider),
      registerAgentHarness: (harness: unknown) => harnesses.push(harness),
      registerCli,
      registerTool,
    } as unknown as OpenClawPluginApi);

    expect(providers).toHaveLength(1);
    expect(harnesses).toHaveLength(1);
    expect(registerCli).toHaveBeenCalledOnce();
    expect(registerTool).not.toHaveBeenCalled();
  });
});
