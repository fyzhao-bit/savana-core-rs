import { MAX_INBOUND_TEXT_BYTES } from "./protocol.js";

const FORBIDDEN_INVENTORY_FIELDS = [
  "tools",
  "mcp",
  "mcpServers",
  "toolCatalog",
  "crestodianTool",
] as const;

export class InboundSelectionError extends Error {
  constructor() {
    super("unsupported Savana inbound turn");
    this.name = "InboundSelectionError";
  }
}

export function selectInboundText(params: unknown): string {
  const record = asRecord(params);
  if (
    record["trigger"] !== "user" ||
    record["currentInboundEventKind"] !== "user_request" ||
    record["currentInboundAudio"] === true
  ) {
    throw new InboundSelectionError();
  }
  const transcriptPrompt = record["transcriptPrompt"];
  if (
    typeof transcriptPrompt !== "string" ||
    transcriptPrompt.length === 0 ||
    transcriptPrompt.includes("\0") ||
    Buffer.byteLength(transcriptPrompt, "utf8") > MAX_INBOUND_TEXT_BYTES
  ) {
    throw new InboundSelectionError();
  }
  const inbound = asRecord(record["currentInboundContext"]);
  if (
    inbound["text"] !== transcriptPrompt ||
    inbound["resumableText"] !== undefined ||
    (inbound["injectedGoalContexts"] !== undefined &&
      (!Array.isArray(inbound["injectedGoalContexts"]) ||
        inbound["injectedGoalContexts"].length > 0))
  ) {
    throw new InboundSelectionError();
  }
  for (const field of ["images", "imageOrder", "clientTools", "toolsAllow"] as const) {
    const value = record[field];
    if (value !== undefined && (!Array.isArray(value) || value.length > 0)) {
      throw new InboundSelectionError();
    }
  }
  for (const field of FORBIDDEN_INVENTORY_FIELDS) {
    const value = record[field];
    if (value !== undefined && value !== null) throw new InboundSelectionError();
  }
  return transcriptPrompt;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InboundSelectionError();
  }
  return value as Record<string, unknown>;
}
