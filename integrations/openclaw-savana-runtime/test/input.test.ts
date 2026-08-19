import { describe, expect, it } from "vitest";

import { InboundSelectionError, selectInboundText } from "../src/input.js";

function input(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    trigger: "user",
    currentInboundEventKind: "user_request",
    transcriptPrompt: "current request",
    currentInboundContext: { text: "current request" },
    prompt: "SYSTEM + MEMORY + current request",
    images: [],
    imageOrder: [],
    clientTools: [],
    toolsAllow: [],
    ...overrides,
  };
}

describe("selectInboundText", () => {
  it("returns only matching current transcript text and ignores assembled prompt", () => {
    expect(selectInboundText(input())).toBe("current request");
  });

  it.each([
    ["non-user trigger", { trigger: "cron" }],
    ["room event", { currentInboundEventKind: "room_event" }],
    ["missing transcript", { transcriptPrompt: undefined }],
    ["mismatch", { currentInboundContext: { text: "other" } }],
    ["injected context", { currentInboundContext: { text: "current request", injectedGoalContexts: ["goal"] } }],
    ["malformed injected context", { currentInboundContext: { text: "current request", injectedGoalContexts: "goal" } }],
    ["resumable text", { currentInboundContext: { text: "current request", resumableText: "resume" } }],
    ["images", { images: [{ data: "image" }] }],
    ["image order", { imageOrder: [{ id: "image" }] }],
    ["client tools", { clientTools: [{ name: "browser" }] }],
    ["tool allowlist", { toolsAllow: ["exec"] }],
    ["prepared tools", { tools: [{ name: "mcp_call" }] }],
    ["MCP inventory", { mcpServers: [{ name: "private" }] }],
    ["audio", { currentInboundAudio: true }],
  ])("rejects %s", (_name, overrides) => {
    expect(() => selectInboundText(input(overrides))).toThrow(InboundSelectionError);
  });
});
