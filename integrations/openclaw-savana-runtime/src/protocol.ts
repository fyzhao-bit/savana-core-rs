import {
  BRIDGE_VERSION,
  OPENCLAW_VERSION,
  PROTOCOL_VERSION,
} from "./config.js";

export const MAX_LINE_BYTES = 1024 * 1024;
export const MAX_INBOUND_TEXT_BYTES = 256 * 1024;
export const MAX_RELEASED_TEXT_BYTES = 1024 * 1024;
export const MAX_ID_BYTES = 256;
export const MAX_APPROVAL_DISPLAY_BYTES = 16 * 1024;
export const MAX_REQUEST_ID = Number.MAX_SAFE_INTEGER;

export type ApprovalPurpose =
  | "ingress"
  | "tool_execution"
  | "final_release"
  | "connector_registration";

export type FailureCode =
  | "authentication_failed"
  | "approval_denied"
  | "policy_refused"
  | "cancelled"
  | "deadline_exceeded"
  | "runtime_incompatible"
  | "protocol_failure"
  | "delivery_timeout"
  | "indeterminate"
  | "no_output"
  | "internal_failure";

export type PluginToBridgeMessage =
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "initialize";
      openclaw_version: typeof OPENCLAW_VERSION;
      plugin_version: typeof BRIDGE_VERSION;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "turn.start";
      agent_id: string;
      session_id: string;
      turn_id: string;
      text: string;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "approval.answer";
      turn_request_id: number;
      approval_id: string;
      approved: boolean;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "turn.cancel";
      turn_request_id: number;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "session.reset";
      agent_id: string;
      session_id: string;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "shutdown";
    };

export type BridgeEvent =
  | { event: "planning" }
  | { event: "step_started"; index: number }
  | {
      event: "step_completed";
      index: number;
      status:
        | "succeeded"
        | "effect_succeeded_output_quarantined"
        | "failed_no_effect";
    }
  | { event: "approval_required"; purpose: ApprovalPurpose }
  | { event: "replanning"; count: number }
  | { event: "refused" }
  | { event: "completed" };

export type BridgeToPluginMessage =
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "initialized";
      bridge_version: typeof BRIDGE_VERSION;
    }
  | ({
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "turn.event";
    } & BridgeEvent)
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "approval.request";
      approval_id: string;
      display: string;
      purpose: ApprovalPurpose;
      deadline_unix_ms: number;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "turn.released";
      text: string;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "turn.failed";
      code: FailureCode;
    }
  | {
      protocol_version: typeof PROTOCOL_VERSION;
      request_id: number;
      type: "session.closed";
    };

const INBOUND_KEYS: Record<PluginToBridgeMessage["type"], readonly string[]> = {
  initialize: [
    "protocol_version",
    "request_id",
    "type",
    "openclaw_version",
    "plugin_version",
  ],
  "turn.start": [
    "protocol_version",
    "request_id",
    "type",
    "agent_id",
    "session_id",
    "turn_id",
    "text",
  ],
  "approval.answer": [
    "protocol_version",
    "request_id",
    "type",
    "turn_request_id",
    "approval_id",
    "approved",
  ],
  "turn.cancel": ["protocol_version", "request_id", "type", "turn_request_id"],
  "session.reset": [
    "protocol_version",
    "request_id",
    "type",
    "agent_id",
    "session_id",
  ],
  shutdown: ["protocol_version", "request_id", "type"],
};

const OUTBOUND_KEYS: Record<string, readonly string[]> = {
  initialized: ["protocol_version", "request_id", "type", "bridge_version"],
  "approval.request": [
    "protocol_version",
    "request_id",
    "type",
    "approval_id",
    "display",
    "purpose",
    "deadline_unix_ms",
  ],
  "turn.released": ["protocol_version", "request_id", "type", "text"],
  "turn.failed": ["protocol_version", "request_id", "type", "code"],
  "session.closed": ["protocol_version", "request_id", "type"],
};

const EVENT_KEYS: Record<BridgeEvent["event"], readonly string[]> = {
  planning: ["protocol_version", "request_id", "type", "event"],
  step_started: ["protocol_version", "request_id", "type", "event", "index"],
  step_completed: [
    "protocol_version",
    "request_id",
    "type",
    "event",
    "index",
    "status",
  ],
  approval_required: [
    "protocol_version",
    "request_id",
    "type",
    "event",
    "purpose",
  ],
  replanning: ["protocol_version", "request_id", "type", "event", "count"],
  refused: ["protocol_version", "request_id", "type", "event"],
  completed: ["protocol_version", "request_id", "type", "event"],
};

const PURPOSES = new Set<ApprovalPurpose>([
  "ingress",
  "tool_execution",
  "final_release",
  "connector_registration",
]);
const STATUSES = new Set([
  "succeeded",
  "effect_succeeded_output_quarantined",
  "failed_no_effect",
]);
const FAILURE_CODES = new Set<FailureCode>([
  "authentication_failed",
  "approval_denied",
  "policy_refused",
  "cancelled",
  "deadline_exceeded",
  "runtime_incompatible",
  "protocol_failure",
  "delivery_timeout",
  "indeterminate",
  "no_output",
  "internal_failure",
]);

export class ProtocolError extends Error {
  constructor() {
    super("Savana bridge protocol failure");
    this.name = "ProtocolError";
  }
}

export function encodeBridgeMessage(message: PluginToBridgeMessage): string {
  const value = record(message);
  const kind = value["type"];
  if (typeof kind !== "string" || !Object.hasOwn(INBOUND_KEYS, kind)) {
    throw new ProtocolError();
  }
  exactKeys(value, INBOUND_KEYS[kind as PluginToBridgeMessage["type"]]);
  common(value);
  validateInbound(value, kind as PluginToBridgeMessage["type"]);
  const encoded = `${stableJson(value)}\n`;
  if (Buffer.byteLength(encoded, "utf8") > MAX_LINE_BYTES) {
    throw new ProtocolError();
  }
  return encoded;
}

export function decodeBridgeMessage(line: string | Buffer): BridgeToPluginMessage {
  const bytes = Buffer.isBuffer(line) ? line : Buffer.from(line, "utf8");
  if (
    bytes.length === 0 ||
    bytes.length > MAX_LINE_BYTES ||
    bytes.at(-1) !== 0x0a ||
    bytes.at(-2) === 0x0d ||
    bytes.subarray(0, -1).includes(0x0a)
  ) {
    throw new ProtocolError();
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, -1));
  } catch {
    throw new ProtocolError();
  }
  const value = record(new StrictJsonParser(source).parse());
  const kind = value["type"];
  if (typeof kind !== "string") {
    throw new ProtocolError();
  }
  if (kind === "turn.event") {
    const event = value["event"];
    if (typeof event !== "string" || !Object.hasOwn(EVENT_KEYS, event)) {
      throw new ProtocolError();
    }
    exactKeys(value, EVENT_KEYS[event as BridgeEvent["event"]]);
  } else {
    const keys = OUTBOUND_KEYS[kind];
    if (keys === undefined) {
      throw new ProtocolError();
    }
    exactKeys(value, keys);
  }
  common(value);
  validateOutbound(value, kind);
  return value as BridgeToPluginMessage;
}

function validateInbound(
  value: Record<string, unknown>,
  kind: PluginToBridgeMessage["type"],
): void {
  switch (kind) {
    case "initialize":
      if (
        value["openclaw_version"] !== OPENCLAW_VERSION ||
        value["plugin_version"] !== BRIDGE_VERSION
      ) {
        throw new ProtocolError();
      }
      break;
    case "turn.start":
      boundedId(value["agent_id"]);
      boundedId(value["session_id"]);
      boundedId(value["turn_id"]);
      boundedString(value["text"], MAX_INBOUND_TEXT_BYTES);
      break;
    case "approval.answer":
      requestId(value["turn_request_id"]);
      boundedString(value["approval_id"], MAX_ID_BYTES);
      if (typeof value["approved"] !== "boolean") throw new ProtocolError();
      break;
    case "turn.cancel":
      requestId(value["turn_request_id"]);
      break;
    case "session.reset":
      boundedId(value["agent_id"]);
      boundedId(value["session_id"]);
      break;
    case "shutdown":
      break;
  }
}

function validateOutbound(value: Record<string, unknown>, kind: string): void {
  switch (kind) {
    case "initialized":
      if (value["bridge_version"] !== BRIDGE_VERSION) throw new ProtocolError();
      break;
    case "turn.event": {
      const event = value["event"];
      if (event === "step_started" || event === "step_completed") {
        boundedU32(value["index"]);
      }
      if (event === "step_completed" && !STATUSES.has(value["status"] as string)) {
        throw new ProtocolError();
      }
      if (event === "approval_required" && !PURPOSES.has(value["purpose"] as ApprovalPurpose)) {
        throw new ProtocolError();
      }
      if (event === "replanning") boundedU32(value["count"]);
      break;
    }
    case "approval.request":
      boundedString(value["approval_id"], MAX_ID_BYTES);
      boundedString(value["display"], MAX_APPROVAL_DISPLAY_BYTES);
      if (!PURPOSES.has(value["purpose"] as ApprovalPurpose)) throw new ProtocolError();
      if (
        !Number.isSafeInteger(value["deadline_unix_ms"]) ||
        (value["deadline_unix_ms"] as number) <= 0
      ) {
        throw new ProtocolError();
      }
      break;
    case "turn.released":
      boundedString(value["text"], MAX_RELEASED_TEXT_BYTES);
      break;
    case "turn.failed":
      if (!FAILURE_CODES.has(value["code"] as FailureCode)) throw new ProtocolError();
      break;
    case "session.closed":
      break;
    default:
      throw new ProtocolError();
  }
}

function common(value: Record<string, unknown>): void {
  if (value["protocol_version"] !== PROTOCOL_VERSION) throw new ProtocolError();
  requestId(value["request_id"]);
}

function requestId(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > MAX_REQUEST_ID) {
    throw new ProtocolError();
  }
}

function boundedU32(value: unknown): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffff_ffff) {
    throw new ProtocolError();
  }
}

function boundedString(value: unknown, maximum: number): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    Buffer.byteLength(value, "utf8") > maximum
  ) {
    throw new ProtocolError();
  }
}

function boundedId(value: unknown): asserts value is string {
  boundedString(value, MAX_ID_BYTES);
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) throw new ProtocolError();
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    throw new ProtocolError();
  }
}

function record(value: unknown): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new ProtocolError();
  }
  return value as Record<string, unknown>;
}

function stableJson(value: Record<string, unknown>): string {
  const sorted = Object.fromEntries(
    Object.entries(value).toSorted(([left], [right]) => left.localeCompare(right)),
  );
  try {
    return JSON.stringify(sorted);
  } catch {
    throw new ProtocolError();
  }
}

class StrictJsonParser {
  readonly #source: string;
  #position = 0;

  constructor(source: string) {
    this.#source = source;
  }

  parse(): unknown {
    try {
      this.#space();
      const value = this.#value();
      this.#space();
      if (this.#position !== this.#source.length) throw new ProtocolError();
      return value;
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      throw new ProtocolError();
    }
  }

  #value(): unknown {
    const next = this.#source[this.#position];
    if (next === "{") return this.#object();
    if (next === "[") return this.#array();
    if (next === '"') return this.#string();
    if (next === "t") return this.#literal("true", true);
    if (next === "f") return this.#literal("false", false);
    if (next === "n") return this.#literal("null", null);
    return this.#number();
  }

  #object(): Record<string, unknown> {
    this.#position += 1;
    this.#space();
    const output: Record<string, unknown> = {};
    const keys = new Set<string>();
    if (this.#take("}")) return output;
    while (true) {
      if (this.#source[this.#position] !== '"') throw new ProtocolError();
      const key = this.#string();
      if (keys.has(key)) throw new ProtocolError();
      keys.add(key);
      this.#space();
      if (!this.#take(":")) throw new ProtocolError();
      this.#space();
      output[key] = this.#value();
      this.#space();
      if (this.#take("}")) return output;
      if (!this.#take(",")) throw new ProtocolError();
      this.#space();
    }
  }

  #array(): unknown[] {
    this.#position += 1;
    this.#space();
    const output: unknown[] = [];
    if (this.#take("]")) return output;
    while (true) {
      output.push(this.#value());
      this.#space();
      if (this.#take("]")) return output;
      if (!this.#take(",")) throw new ProtocolError();
      this.#space();
    }
  }

  #string(): string {
    const start = this.#position;
    this.#position += 1;
    while (this.#position < this.#source.length) {
      const character = this.#source[this.#position];
      if (character === '"') {
        this.#position += 1;
        return JSON.parse(this.#source.slice(start, this.#position)) as string;
      }
      if (character === "\\") {
        this.#position += 1;
        const escape = this.#source[this.#position];
        if (escape === "u") {
          const digits = this.#source.slice(this.#position + 1, this.#position + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) throw new ProtocolError();
          this.#position += 5;
          continue;
        }
        if (escape === undefined || !'"\\/bfnrt'.includes(escape)) {
          throw new ProtocolError();
        }
        this.#position += 1;
        continue;
      }
      if (character === undefined || character.codePointAt(0)! < 0x20) {
        throw new ProtocolError();
      }
      this.#position += 1;
    }
    throw new ProtocolError();
  }

  #number(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.#source.slice(this.#position),
    );
    if (match === null) throw new ProtocolError();
    this.#position += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new ProtocolError();
    return value;
  }

  #literal<T>(source: string, value: T): T {
    if (!this.#source.startsWith(source, this.#position)) throw new ProtocolError();
    this.#position += source.length;
    return value;
  }

  #space(): void {
    while (/\s/u.test(this.#source[this.#position] ?? "")) this.#position += 1;
  }

  #take(character: string): boolean {
    if (this.#source[this.#position] !== character) return false;
    this.#position += 1;
    return true;
  }
}
