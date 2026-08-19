import { spawn as nodeSpawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";

import type { SavanaPluginConfig } from "./config.js";
import {
  BRIDGE_VERSION,
  OPENCLAW_VERSION,
  PROTOCOL_VERSION,
} from "./config.js";
import {
  MAX_LINE_BYTES,
  type ApprovalPurpose,
  type BridgeEvent,
  type BridgeToPluginMessage,
  type FailureCode,
  type PluginToBridgeMessage,
  ProtocolError,
  decodeBridgeMessage,
  encodeBridgeMessage,
} from "./protocol.js";

export const PRODUCT_AUTH_BROKER_FD = 3;
const INITIALIZE_TIMEOUT_MS = 10_000;
const TERMINATE_SIGNAL = "SIGTERM";

export interface ChildProcessLike {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  kill(signal?: NodeJS.Signals): boolean;
  on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: "error", listener: (error: Error) => void): this;
}

export interface SpawnBridgeOptions {
  readonly cwd?: string;
  readonly env: NodeJS.ProcessEnv;
  readonly shell: false;
  readonly stdio: ["pipe", "pipe", "pipe", number];
}

export type SpawnBridge = (
  command: string,
  arguments_: readonly string[],
  options: SpawnBridgeOptions,
) => ChildProcessLike;

export interface ApprovalPrompt {
  readonly approvalId: string;
  readonly display: string;
  readonly purpose: ApprovalPurpose;
  readonly deadlineUnixMs: number;
}

export interface RunTurnOptions {
  readonly agentId: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly text: string;
  readonly signal?: AbortSignal;
  readonly onEvent: (event: BridgeEvent) => void | Promise<void>;
  readonly onApproval: (request: ApprovalPrompt) => Promise<boolean>;
}

export interface ReleasedTurn {
  readonly text: string;
}

export interface DoctorSnapshot {
  readonly activeConnectorCount: number;
  readonly releaseTargetUrl: string;
  readonly serviceOrigins: readonly [string, string, string];
}

export class BridgeFailure extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode) {
    super(`Savana bridge failed: ${code}`);
    this.name = "BridgeFailure";
    this.code = code;
  }
}

interface PendingInitialize {
  readonly type: "initialize";
  readonly resolve: () => void;
  readonly reject: (error: BridgeFailure) => void;
}

interface PendingTurn {
  readonly type: "turn";
  readonly options: RunTurnOptions;
  readonly resolve: (result: ReleasedTurn) => void;
  readonly reject: (error: BridgeFailure) => void;
  readonly abort?: () => void;
}

interface PendingReset {
  readonly type: "reset";
  readonly resolve: () => void;
  readonly reject: (error: BridgeFailure) => void;
}

interface PendingDoctor {
  readonly type: "doctor";
  readonly resolve: (snapshot: DoctorSnapshot) => void;
  readonly reject: (error: BridgeFailure) => void;
}

type Pending = PendingInitialize | PendingTurn | PendingReset | PendingDoctor;

export interface BridgeProcessDependencies {
  readonly spawn?: SpawnBridge;
  readonly parentEnvironment?: NodeJS.ProcessEnv;
  readonly doctorOnly?: boolean;
  readonly diagnostic?: (code: "bridge_stderr" | "bridge_exit" | "bridge_protocol") => void;
}

export class BridgeProcess {
  readonly #config: SavanaPluginConfig;
  readonly #spawn: SpawnBridge;
  readonly #parentEnvironment: NodeJS.ProcessEnv;
  readonly #diagnostic: NonNullable<BridgeProcessDependencies["diagnostic"]>;
  readonly #doctorOnly: boolean;
  readonly #pending = new Map<number, Pending>();
  readonly #terminalRequestIds = new Set<number>();
  readonly #approvalIds = new Set<string>();
  #child: ChildProcessLike | undefined;
  #buffer = Buffer.alloc(0);
  #requestId = 0;
  #initialized = false;
  #closed = false;
  #disposing = false;
  #stderrReported = false;

  constructor(config: SavanaPluginConfig, dependencies: BridgeProcessDependencies = {}) {
    this.#config = config;
    this.#spawn = dependencies.spawn ?? realSpawn;
    this.#parentEnvironment = dependencies.parentEnvironment ?? process.env;
    this.#diagnostic = dependencies.diagnostic ?? (() => undefined);
    this.#doctorOnly = dependencies.doctorOnly === true;
  }

  get closed(): boolean {
    return this.#closed;
  }

  async start(): Promise<void> {
    if (this.#closed || this.#child !== undefined) {
      throw new BridgeFailure("runtime_incompatible");
    }
    let child: ChildProcessLike;
    try {
      child = this.#spawn(
        this.#config.pythonExecutable,
        [
          "-m",
          "savana.openclaw_bridge",
          this.#doctorOnly ? "--doctor-config" : "--config",
          this.#config.bridgeConfigPath,
        ],
        {
          ...(this.#config.bridgeWorkingDirectory === undefined
            ? {}
            : { cwd: this.#config.bridgeWorkingDirectory }),
          env: childEnvironment(this.#parentEnvironment),
          shell: false,
          stdio: ["pipe", "pipe", "pipe", PRODUCT_AUTH_BROKER_FD],
        },
      );
    } catch {
      this.#closed = true;
      throw new BridgeFailure("runtime_incompatible");
    }
    this.#child = child;
    child.stdout.on("data", (chunk: Buffer | string) => this.#onStdout(chunk));
    child.stderr.on("data", () => {
      if (this.#stderrReported) return;
      this.#stderrReported = true;
      this.#diagnostic("bridge_stderr");
    });
    child.on("error", () => this.#poison("bridge_exit"));
    child.on("exit", () => this.#poison("bridge_exit"));

    const requestId = this.#nextRequestId();
    const initialized = new Promise<void>((resolve, reject) => {
      this.#pending.set(requestId, {
        type: "initialize",
        resolve,
        reject,
      });
    });
    this.#write({
      protocol_version: PROTOCOL_VERSION,
      request_id: requestId,
      type: "initialize",
      openclaw_version: OPENCLAW_VERSION,
      plugin_version: BRIDGE_VERSION,
    });
    await withTimeout(initialized, INITIALIZE_TIMEOUT_MS, () => {
      this.#poison("bridge_protocol");
    });
  }

  async runTurn(options: RunTurnOptions): Promise<ReleasedTurn> {
    this.#requireReady();
    if (options.signal?.aborted === true) throw new BridgeFailure("cancelled");
    const requestId = this.#nextRequestId();
    const promise = new Promise<ReleasedTurn>((resolve, reject) => {
      const pending: PendingTurn = {
        type: "turn",
        options,
        resolve,
        reject,
        ...(options.signal === undefined
          ? {}
          : {
              abort: () => {
                if (this.#pending.get(requestId) !== pending) return;
                try {
                  this.#write({
                    protocol_version: PROTOCOL_VERSION,
                    request_id: this.#nextRequestId(),
                    type: "turn.cancel",
                    turn_request_id: requestId,
                  });
                } catch {
                  this.#poison("bridge_protocol");
                }
              },
            }),
      };
      this.#pending.set(requestId, pending);
      if (pending.abort !== undefined) {
        options.signal?.addEventListener("abort", pending.abort, { once: true });
      }
    });
    try {
      this.#write({
        protocol_version: PROTOCOL_VERSION,
        request_id: requestId,
        type: "turn.start",
        agent_id: options.agentId,
        session_id: options.sessionId,
        turn_id: options.turnId,
        text: options.text,
      });
    } catch (error) {
      this.#deletePending(requestId);
      throw error;
    }
    return promise;
  }

  async reset(agentId: string, sessionId: string): Promise<void> {
    this.#requireReady();
    const requestId = this.#nextRequestId();
    const promise = new Promise<void>((resolve, reject) => {
      this.#pending.set(requestId, { type: "reset", resolve, reject });
    });
    try {
      this.#write({
        protocol_version: PROTOCOL_VERSION,
        request_id: requestId,
        type: "session.reset",
        agent_id: agentId,
        session_id: sessionId,
      });
    } catch (error) {
      this.#pending.delete(requestId);
      throw error;
    }
    return promise;
  }

  async doctor(): Promise<DoctorSnapshot> {
    this.#requireReady();
    const requestId = this.#nextRequestId();
    const promise = new Promise<DoctorSnapshot>((resolve, reject) => {
      this.#pending.set(requestId, { type: "doctor", resolve, reject });
    });
    try {
      this.#write({
        protocol_version: PROTOCOL_VERSION,
        request_id: requestId,
        type: "doctor.request",
      });
    } catch (error) {
      this.#pending.delete(requestId);
      throw error;
    }
    return promise;
  }

  async dispose(): Promise<void> {
    if (this.#disposing) return;
    this.#disposing = true;
    const child = this.#child;
    if (!this.#closed && child !== undefined && this.#initialized) {
      try {
        this.#write({
          protocol_version: PROTOCOL_VERSION,
          request_id: this.#nextRequestId(),
          type: "shutdown",
        });
      } catch {
        // The process is closed below regardless.
      }
    }
    this.#closed = true;
    this.#rejectAll(new BridgeFailure("cancelled"));
    child?.kill(TERMINATE_SIGNAL);
  }

  #onStdout(chunk: Buffer | string): void {
    if (this.#closed) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    this.#buffer = Buffer.concat([this.#buffer, bytes]);
    if (this.#buffer.length > MAX_LINE_BYTES && !this.#buffer.includes(0x0a)) {
      this.#poison("bridge_protocol");
      return;
    }
    while (!this.#closed) {
      const newline = this.#buffer.indexOf(0x0a);
      if (newline < 0) return;
      const line = this.#buffer.subarray(0, newline + 1);
      this.#buffer = this.#buffer.subarray(newline + 1);
      try {
        this.#handle(decodeBridgeMessage(line));
      } catch {
        this.#poison("bridge_protocol");
      }
    }
  }

  #handle(message: BridgeToPluginMessage): void {
    if (this.#terminalRequestIds.has(message.request_id)) throw new ProtocolError();
    const pending = this.#pending.get(message.request_id);
    if (pending === undefined) throw new ProtocolError();

    if (message.type === "initialized") {
      if (pending.type !== "initialize" || this.#initialized) throw new ProtocolError();
      this.#pending.delete(message.request_id);
      this.#initialized = true;
      pending.resolve();
      return;
    }
    if (!this.#initialized) throw new ProtocolError();
    if (message.type === "session.closed") {
      if (pending.type !== "reset") throw new ProtocolError();
      this.#pending.delete(message.request_id);
      this.#terminalRequestIds.add(message.request_id);
      pending.resolve();
      return;
    }
    if (message.type === "doctor.result") {
      if (pending.type !== "doctor") throw new ProtocolError();
      this.#pending.delete(message.request_id);
      this.#terminalRequestIds.add(message.request_id);
      pending.resolve({
        activeConnectorCount: message.active_connector_count,
        releaseTargetUrl: message.release_target_url,
        serviceOrigins: message.service_origins,
      });
      return;
    }
    if (message.type === "doctor.failed") {
      if (pending.type !== "doctor") throw new ProtocolError();
      this.#pending.delete(message.request_id);
      this.#terminalRequestIds.add(message.request_id);
      pending.reject(new BridgeFailure(message.code));
      return;
    }
    if (pending.type !== "turn") throw new ProtocolError();
    if (message.type === "turn.event") {
      const { protocol_version: _version, request_id: _id, type: _type, ...event } =
        message;
      void Promise.resolve(pending.options.onEvent(event)).catch(() => {
        this.#poison("bridge_protocol");
      });
      return;
    }
    if (message.type === "approval.request") {
      if (this.#approvalIds.has(message.approval_id)) throw new ProtocolError();
      this.#approvalIds.add(message.approval_id);
      void this.#answerApproval(message.request_id, pending, message);
      return;
    }
    if (message.type === "turn.released") {
      this.#finishTurn(message.request_id, pending);
      pending.resolve({ text: message.text });
      return;
    }
    if (message.type === "turn.failed") {
      this.#finishTurn(message.request_id, pending);
      pending.reject(new BridgeFailure(message.code));
      return;
    }
    throw new ProtocolError();
  }

  async #answerApproval(
    turnRequestId: number,
    pending: PendingTurn,
    message: Extract<BridgeToPluginMessage, { type: "approval.request" }>,
  ): Promise<void> {
    let approved = false;
    const remaining = Math.max(0, message.deadline_unix_ms - Date.now());
    if (remaining > 0) {
      try {
        approved =
          (await withTimeout(
            pending.options.onApproval({
              approvalId: message.approval_id,
              display: message.display,
              purpose: message.purpose,
              deadlineUnixMs: message.deadline_unix_ms,
            }),
            Math.min(remaining, this.#config.approvalTimeoutSeconds * 1000),
            () => undefined,
          )) === true;
      } catch {
        approved = false;
      }
    }
    if (this.#pending.get(turnRequestId) !== pending || this.#closed) return;
    try {
      this.#write({
        protocol_version: PROTOCOL_VERSION,
        request_id: this.#nextRequestId(),
        type: "approval.answer",
        turn_request_id: turnRequestId,
        approval_id: message.approval_id,
        approved,
      });
    } catch {
      this.#poison("bridge_protocol");
    }
  }

  #finishTurn(requestId: number, pending: PendingTurn): void {
    this.#deletePending(requestId);
    this.#terminalRequestIds.add(requestId);
    if (pending.abort !== undefined) {
      pending.options.signal?.removeEventListener("abort", pending.abort);
    }
  }

  #deletePending(requestId: number): void {
    const pending = this.#pending.get(requestId);
    if (pending?.type === "turn" && pending.abort !== undefined) {
      pending.options.signal?.removeEventListener("abort", pending.abort);
    }
    this.#pending.delete(requestId);
  }

  #write(message: PluginToBridgeMessage): void {
    if (this.#closed || this.#child === undefined || !this.#child.stdin.writable) {
      throw new BridgeFailure("protocol_failure");
    }
    const accepted = this.#child.stdin.write(encodeBridgeMessage(message), "utf8");
    if (!accepted && this.#child.stdin.destroyed) {
      throw new BridgeFailure("protocol_failure");
    }
  }

  #nextRequestId(): number {
    this.#requestId += 1;
    if (!Number.isSafeInteger(this.#requestId)) {
      this.#poison("bridge_protocol");
      throw new BridgeFailure("protocol_failure");
    }
    return this.#requestId;
  }

  #requireReady(): void {
    if (this.#closed || !this.#initialized || this.#child === undefined) {
      throw new BridgeFailure("runtime_incompatible");
    }
  }

  #poison(code: "bridge_exit" | "bridge_protocol"): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#diagnostic(code);
    const initialized = this.#initialized;
    this.#child?.kill(TERMINATE_SIGNAL);
    this.#rejectAll(
      new BridgeFailure(initialized ? "indeterminate" : "runtime_incompatible"),
    );
  }

  #rejectAll(error: BridgeFailure): void {
    for (const [requestId, pending] of this.#pending) {
      this.#deletePending(requestId);
      pending.reject(error);
    }
  }
}

function childEnvironment(parent: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const output: NodeJS.ProcessEnv = {
    PYTHONNOUSERSITE: "1",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
  };
  for (const key of ["LANG", "LC_ALL", "LC_CTYPE", "TZ"] as const) {
    const value = parent[key];
    if (typeof value === "string" && value.length <= 256 && !value.includes("\0")) {
      output[key] = value;
    }
  }
  return output;
}

function realSpawn(
  command: string,
  arguments_: readonly string[],
  options: SpawnBridgeOptions,
): ChildProcessLike {
  return nodeSpawn(command, [...arguments_], options) as ChildProcessLike;
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      onTimeout();
      reject(new BridgeFailure("deadline_exceeded"));
    }, timeoutMs);
    timeout.unref();
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}
