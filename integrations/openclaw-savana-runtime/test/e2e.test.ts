import type { AgentHarnessAttemptParams } from "openclaw/plugin-sdk/agent-harness-runtime";
import { describe, expect, it } from "vitest";

import {
  BridgeFailure,
  type ReleasedTurn,
  type RunTurnOptions,
} from "../src/bridge-process.js";
import { createSavanaHarness } from "../src/harness.js";
import type { FailureCode } from "../src/protocol.js";

class ScenarioBridge {
  readonly start = async () => undefined;
  readonly reset = async () => undefined;
  readonly dispose = async () => undefined;
  scenario: "released" | FailureCode = "released";

  async runTurn(options: RunTurnOptions): Promise<ReleasedTurn> {
    if (this.scenario === "released") {
      return { text: "journaled release bytes" };
    }
    throw new BridgeFailure(this.scenario);
  }
}

function attempt(overrides: Record<string, unknown> = {}): AgentHarnessAttemptParams {
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
    transcriptPrompt: "current inbound text",
    currentInboundContext: { text: "current inbound text" },
    prompt: "assembled prompt that must not cross the boundary",
    images: [],
    imageOrder: [],
    clientTools: [],
    toolsAllow: [],
    model: { api: "openai-responses" },
    ...overrides,
  } as unknown as AgentHarnessAttemptParams;
}

describe("released-only end-to-end harness boundary", () => {
  it("constructs an assistant message only from turn.released bytes", async () => {
    const bridge = new ScenarioBridge();
    const harness = createSavanaHarness(bridge, {
      activate: () => undefined,
      deactivate: () => undefined,
    });
    const result = await harness.runAttempt(attempt());
    expect(result.assistantTexts).toEqual(["journaled release bytes"]);
    expect(result.lastAssistant?.content).toEqual([
      { type: "text", text: "journaled release bytes" },
    ]);
  });

  it.each<readonly [string, FailureCode]>([
    ["approval denial", "approval_denied"],
    ["failed_no_effect", "internal_failure"],
    ["quarantined output", "indeterminate"],
    ["indeterminate execution", "indeterminate"],
    ["bridge crash", "internal_failure"],
    ["receiver crash", "delivery_timeout"],
    ["duplicate delivery", "indeterminate"],
    ["cross-session delivery", "indeterminate"],
  ])("emits no assistant reply for %s", async (_name, code) => {
    const bridge = new ScenarioBridge();
    bridge.scenario = code;
    const harness = createSavanaHarness(bridge, {
      activate: () => undefined,
      deactivate: () => undefined,
    });
    await expect(harness.runAttempt(attempt())).rejects.toMatchObject({ code });
  });

  it("returns an empty aborted result on cancellation", async () => {
    const bridge = new ScenarioBridge();
    bridge.scenario = "cancelled";
    const harness = createSavanaHarness(bridge, {
      activate: () => undefined,
      deactivate: () => undefined,
    });
    const controller = new AbortController();
    controller.abort();
    const result = await harness.runAttempt(attempt({ abortSignal: controller.signal }));
    expect(result.aborted).toBe(true);
    expect(result.assistantTexts).toEqual([]);
    expect(result.lastAssistant).toBeUndefined();
  });
});
