import { describe, expect, it } from "vitest";

import {
  MAX_INBOUND_TEXT_BYTES,
  MAX_LINE_BYTES,
  ProtocolError,
  decodeBridgeMessage,
  encodeBridgeMessage,
} from "../src/protocol.js";

describe("bridge protocol", () => {
  it("encodes the closed initialize and turn unions", () => {
    expect(
      encodeBridgeMessage({
        protocol_version: 1,
        request_id: 1,
        type: "initialize",
        openclaw_version: "2026.7.1-2",
        plugin_version: "0.1.0",
      }),
    ).toBe(
      '{"openclaw_version":"2026.7.1-2","plugin_version":"0.1.0","protocol_version":1,"request_id":1,"type":"initialize"}\n',
    );

    expect(() =>
      encodeBridgeMessage({
        protocol_version: 1,
        request_id: 2,
        type: "turn.start",
        agent_id: "agent",
        session_id: "session",
        turn_id: "turn",
        text: "x".repeat(MAX_INBOUND_TEXT_BYTES + 1),
      }),
    ).toThrow(ProtocolError);
  });

  it("decodes only compatible, exact outbound messages", () => {
    expect(
      decodeBridgeMessage(
        '{"bridge_version":"0.1.0","protocol_version":1,"request_id":1,"type":"initialized"}\n',
      ),
    ).toEqual({
      bridge_version: "0.1.0",
      protocol_version: 1,
      request_id: 1,
      type: "initialized",
    });

    for (const line of [
      '{"bridge_version":"0.2.0","protocol_version":1,"request_id":1,"type":"initialized"}\n',
      '{"bridge_version":"0.1.0","extra":true,"protocol_version":1,"request_id":1,"type":"initialized"}\n',
      '{"bridge_version":"0.1.0","bridge_version":"0.1.0","protocol_version":1,"request_id":1,"type":"initialized"}\n',
      '{"protocol_version":1,"request_id":2,"type":"turn.released","text":NaN}\n',
      "[]\n",
      "not-json\n",
    ]) {
      expect(() => decodeBridgeMessage(line)).toThrow(ProtocolError);
    }
  });

  it("enforces the encoded line bound before parsing", () => {
    expect(() => decodeBridgeMessage(" ".repeat(MAX_LINE_BYTES + 1))).toThrow(
      ProtocolError,
    );
  });
});
