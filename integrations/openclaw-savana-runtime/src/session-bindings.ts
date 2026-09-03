import { randomBytes } from "node:crypto";

export type RandomBindingBytes = () => Buffer;

export class SessionBindings {
  readonly #bindings = new Map<string, Map<string, string>>();
  readonly #random: RandomBindingBytes;

  constructor(random: RandomBindingBytes = () => randomBytes(32)) {
    this.#random = random;
  }

  getOrCreate(agentId: string, openClawSessionId: string): string {
    let sessions = this.#bindings.get(agentId);
    if (sessions === undefined) {
      sessions = new Map();
      this.#bindings.set(agentId, sessions);
    }
    const existing = sessions.get(openClawSessionId);
    if (existing !== undefined) return existing;
    const bytes = this.#random();
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length !== 32 ||
      bytes.every((byte) => byte === 0)
    ) {
      throw new Error("Savana session binding unavailable");
    }
    const binding = bytes.toString("base64url");
    sessions.set(openClawSessionId, binding);
    return binding;
  }

  has(agentId: string, openClawSessionId: string): boolean {
    return this.#bindings.get(agentId)?.has(openClawSessionId) === true;
  }

  retire(agentId: string, openClawSessionId: string): boolean {
    const sessions = this.#bindings.get(agentId);
    if (sessions === undefined) return false;
    const retired = sessions.delete(openClawSessionId);
    if (sessions.size === 0) this.#bindings.delete(agentId);
    return retired;
  }

  async reset(
    agentId: string,
    openClawSessionId: string,
    resetBridgeSession: (agentId: string, bridgeSessionId: string) => Promise<void>,
  ): Promise<void> {
    const sessions = this.#bindings.get(agentId);
    const binding = sessions?.get(openClawSessionId);
    if (binding === undefined) return;
    try {
      await resetBridgeSession(agentId, binding);
    } finally {
      this.retire(agentId, openClawSessionId);
    }
  }

  clear(): void {
    this.#bindings.clear();
  }
}
