import { describe, expect, it, vi } from "vitest";

import { SessionBindings } from "../src/session-bindings.js";

describe("SessionBindings", () => {
  it("keeps one opaque in-memory binding per agent and OpenClaw session", () => {
    let counter = 0;
    const bindings = new SessionBindings(() => Buffer.alloc(32, ++counter));

    const first = bindings.getOrCreate("agent-a", "../../user-session");
    expect(bindings.getOrCreate("agent-a", "../../user-session")).toBe(first);
    expect(bindings.getOrCreate("agent-b", "../../user-session")).not.toBe(first);
    expect(first).not.toContain("user-session");
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("retires failed bindings and never resurrects them in a new process", async () => {
    let counter = 0;
    const random = () => Buffer.alloc(32, ++counter);
    const bindings = new SessionBindings(random);
    const original = bindings.getOrCreate("agent", "session");
    expect(bindings.retire("agent", "session")).toBe(true);
    expect(bindings.getOrCreate("agent", "session")).not.toBe(original);

    const reset = vi.fn(async () => undefined);
    const active = bindings.getOrCreate("agent", "session");
    await bindings.reset("agent", "session", reset);
    expect(reset).toHaveBeenCalledWith("agent", active);
    expect(bindings.has("agent", "session")).toBe(false);

    const restarted = new SessionBindings(random);
    expect(restarted.getOrCreate("agent", "session")).not.toBe(active);
  });

  it("rejects an all-zero or malformed entropy result", () => {
    for (const random of [
      () => Buffer.alloc(32),
      () => Buffer.alloc(31, 1),
    ]) {
      expect(() =>
        new SessionBindings(random).getOrCreate("agent", "session"),
      ).toThrow("Savana session binding unavailable");
    }
  });
});
