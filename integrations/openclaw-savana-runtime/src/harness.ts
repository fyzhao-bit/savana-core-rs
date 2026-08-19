import type {
  AgentHarness,
  AgentHarnessAttemptParams,
  AgentHarnessAttemptResult,
  AgentHarnessUserInputQuestion,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  clearActiveEmbeddedRun,
  deliverAgentHarnessUserInputPrompt,
  setActiveEmbeddedRun,
} from "openclaw/plugin-sdk/agent-harness-runtime";

import type {
  ApprovalPrompt,
  BridgeProcess,
  ReleasedTurn,
  RunTurnOptions,
} from "./bridge-process.js";
import { BridgeFailure } from "./bridge-process.js";
import { selectInboundText } from "./input.js";
import {
  SAVANA_HARNESS_ID,
  SAVANA_MODEL_ID,
  SAVANA_PROVIDER_ID,
} from "./provider.js";
import type { BridgeEvent } from "./protocol.js";
import { SessionBindings } from "./session-bindings.js";

interface SavanaBridge {
  readonly closed?: boolean;
  start(): Promise<void>;
  runTurn(options: RunTurnOptions): Promise<ReleasedTurn>;
  reset(agentId: string, sessionId: string): Promise<void>;
  dispose(): Promise<void>;
}

interface ActiveHandle {
  readonly kind: "embedded";
  readonly runId: string;
  queueMessage(text: string): Promise<void>;
  isStreaming(): boolean;
  isStopped(): boolean;
  isAbortable(): boolean;
  isCompacting(): boolean;
  cancel(): void;
  abort(): void;
}

export interface SavanaHarnessDependencies {
  readonly bindings?: SessionBindings;
  readonly deliverApproval?: typeof deliverAgentHarnessUserInputPrompt;
  readonly activate?: (sessionId: string, handle: ActiveHandle, sessionKey?: string, sessionFile?: string) => void;
  readonly deactivate?: (sessionId: string, handle: ActiveHandle, sessionKey?: string, sessionFile?: string) => void;
}

export function createSavanaHarness(
  bridge: SavanaBridge,
  dependencies: SavanaHarnessDependencies = {},
): AgentHarness {
  const bindings = dependencies.bindings ?? new SessionBindings();
  const deliverApproval =
    dependencies.deliverApproval ?? deliverAgentHarnessUserInputPrompt;
  const activate = dependencies.activate ?? setActiveEmbeddedRun;
  const deactivate = dependencies.deactivate ?? clearActiveEmbeddedRun;
  let started: Promise<void> | undefined;

  const ensureStarted = async (): Promise<void> => {
    started ??= bridge.start();
    await started;
  };

  const retire = async (
    agentId: string,
    openClawSessionId: string,
    bridgeSessionId: string,
  ): Promise<void> => {
    bindings.retire(agentId, openClawSessionId);
    if (bridge.closed === true) return;
    try {
      await bridge.reset(agentId, bridgeSessionId);
    } catch {
      // The original terminal failure stays authoritative.
    }
  };

  return {
    id: SAVANA_HARNESS_ID,
    label: "Savana privacy-kernel agent harness",
    deliveryDefaults: { sourceVisibleReplies: "automatic" },
    supports(context) {
      if (
        context.provider === SAVANA_PROVIDER_ID &&
        context.modelId === SAVANA_MODEL_ID &&
        context.requestedRuntime === SAVANA_HARNESS_ID
      ) {
        return { supported: true, priority: 100 };
      }
      return {
        supported: false,
        reason: "requires explicit savana/agent model-scoped runtime selection",
      };
    },
    async runAttempt(params) {
      verifyClaimedAttempt(params);
      const text = selectInboundText(params);
      await ensureStarted();
      const agentId = params.agentId ?? "default";
      const openClawSessionId = params.sessionId;
      const bridgeSessionId = bindings.getOrCreate(agentId, openClawSessionId);
      const approval = new ApprovalCoordinator(params, deliverApproval);
      const localAbort = new AbortController();
      const signal = params.abortSignal
        ? AbortSignal.any([params.abortSignal, localAbort.signal])
        : localAbort.signal;
      let running = true;
      const handle: ActiveHandle = {
        kind: "embedded",
        runId: params.runId,
        queueMessage: async (answer) => {
          if (!approval.answer(answer)) {
            throw new Error("Savana runtime is not awaiting approval");
          }
        },
        isStreaming: () => running,
        isStopped: () => !running,
        isAbortable: () => running,
        isCompacting: () => false,
        cancel: () => localAbort.abort("cancelled"),
        abort: () => localAbort.abort("aborted"),
      };
      params.replyOperation?.attachBackend(handle);
      activate(params.sessionId, handle, params.sessionKey, params.sessionFile);
      params.onExecutionStarted?.();
      try {
        const released = await bridge.runTurn({
          agentId,
          sessionId: bridgeSessionId,
          turnId: params.runId,
          text,
          signal,
          onEvent: async (event) => emitProgress(params, event),
          onApproval: async (request) => approval.request(request),
        });
        return releasedResult(params, released.text);
      } catch (error) {
        approval.cancel();
        if (error instanceof BridgeFailure && error.code === "cancelled") {
          await retire(agentId, openClawSessionId, bridgeSessionId);
          return abortedResult(params);
        }
        await retire(agentId, openClawSessionId, bridgeSessionId);
        throw error instanceof BridgeFailure
          ? error
          : new BridgeFailure("internal_failure");
      } finally {
        running = false;
        approval.cancel();
        deactivate(params.sessionId, handle, params.sessionKey, params.sessionFile);
        params.replyOperation?.detachBackend(handle);
      }
    },
    async reset(params) {
      if (params.sessionId === undefined) return;
      const agentId = params.agentId ?? "default";
      await bindings.reset(agentId, params.sessionId, async (owner, session) => {
        await ensureStarted();
        await bridge.reset(owner, session);
      });
    },
    async dispose() {
      bindings.clear();
      await bridge.dispose();
    },
  };
}

class ApprovalCoordinator {
  readonly #params: AgentHarnessAttemptParams;
  readonly #deliver: typeof deliverAgentHarnessUserInputPrompt;
  #pending:
    | {
        readonly resolve: (approved: boolean) => void;
        readonly timer: NodeJS.Timeout;
      }
    | undefined;

  constructor(
    params: AgentHarnessAttemptParams,
    deliver: typeof deliverAgentHarnessUserInputPrompt,
  ) {
    this.#params = params;
    this.#deliver = deliver;
  }

  async request(request: ApprovalPrompt): Promise<boolean> {
    if (this.#pending !== undefined) return false;
    const remaining = request.deadlineUnixMs - Date.now();
    if (remaining <= 0) return false;
    const questions: readonly AgentHarnessUserInputQuestion[] = [
      {
        id: request.approvalId,
        header: "Savana approval",
        question: request.display,
        isOther: false,
        isSecret: false,
        options: [{ label: "Approve" }, { label: "Deny" }],
      },
    ];
    let resolvePending: (approved: boolean) => void = () => undefined;
    const answer = new Promise<boolean>((resolve) => {
      resolvePending = resolve;
    });
    const timer = setTimeout(() => {
      this.#settle(false);
    }, remaining);
    timer.unref();
    this.#pending = { resolve: resolvePending, timer };
    try {
      await this.#deliver(this.#params, questions);
    } catch {
      this.#settle(false);
    }
    return answer;
  }

  answer(text: string): boolean {
    if (this.#pending === undefined) return false;
    this.#settle(text.trim() === "Approve");
    return true;
  }

  cancel(): void {
    this.#settle(false);
  }

  #settle(approved: boolean): void {
    const pending = this.#pending;
    if (pending === undefined) return;
    this.#pending = undefined;
    clearTimeout(pending.timer);
    pending.resolve(approved);
  }
}

function verifyClaimedAttempt(params: AgentHarnessAttemptParams): void {
  if (
    params.provider !== SAVANA_PROVIDER_ID ||
    params.modelId !== SAVANA_MODEL_ID ||
    params.agentHarnessId !== SAVANA_HARNESS_ID ||
    params.fallbackActive === true ||
    (params.modelFallbacksOverride !== undefined &&
      params.modelFallbacksOverride.length > 0)
  ) {
    throw new BridgeFailure("runtime_incompatible");
  }
}

async function emitProgress(
  params: AgentHarnessAttemptParams,
  event: BridgeEvent,
): Promise<void> {
  await params.onAgentEvent?.({
    stream: "savana.lifecycle",
    data: { ...event },
    ...(params.sessionKey === undefined ? {} : { sessionKey: params.sessionKey }),
  });
}

function releasedResult(
  params: AgentHarnessAttemptParams,
  text: string,
): AgentHarnessAttemptResult {
  const assistant = {
    role: "assistant" as const,
    content: [{ type: "text" as const, text }],
    api: params.model.api,
    provider: SAVANA_PROVIDER_ID,
    model: SAVANA_MODEL_ID,
    usage: emptyUsage(),
    stopReason: "stop" as const,
    timestamp: Date.now(),
  };
  return baseResult(params, {
    assistantTexts: [text],
    messagesSnapshot: [assistant],
    lastAssistant: assistant,
    currentAttemptAssistant: assistant,
  });
}

function abortedResult(params: AgentHarnessAttemptParams): AgentHarnessAttemptResult {
  return {
    ...baseResult(params, {
      assistantTexts: [],
      messagesSnapshot: [],
      lastAssistant: undefined,
      currentAttemptAssistant: undefined,
    }),
    aborted: true,
    externalAbort: params.abortSignal?.aborted === true,
  };
}

function baseResult(
  params: AgentHarnessAttemptParams,
  messages: Pick<
    AgentHarnessAttemptResult,
    | "assistantTexts"
    | "messagesSnapshot"
    | "lastAssistant"
    | "currentAttemptAssistant"
  >,
): AgentHarnessAttemptResult {
  return {
    aborted: false,
    externalAbort: false,
    timedOut: false,
    idleTimedOut: false,
    timedOutDuringCompaction: false,
    promptError: null,
    promptErrorSource: null,
    sessionIdUsed: params.sessionId,
    agentHarnessId: SAVANA_HARNESS_ID,
    ...messages,
    toolMetas: [],
    acceptedSessionSpawns: [],
    didSendViaMessagingTool: false,
    messagingToolSentTexts: [],
    messagingToolSentMediaUrls: [],
    messagingToolSentTargets: [],
    cloudCodeAssistFormatError: false,
    replayMetadata: {
      hadPotentialSideEffects: true,
      replaySafe: false,
    },
    itemLifecycle: {
      startedCount: 1,
      completedCount: 1,
      activeCount: 0,
    },
  };
}

function emptyUsage() {
  return {
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 0,
    cost: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      total: 0,
    },
  };
}

export type { BridgeProcess };
