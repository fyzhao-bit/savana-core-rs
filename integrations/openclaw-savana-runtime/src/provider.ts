import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";

export const SAVANA_PROVIDER_ID = "savana" as const;
export const SAVANA_MODEL_ID = "agent" as const;
export const SAVANA_MODEL_REF = `${SAVANA_PROVIDER_ID}/${SAVANA_MODEL_ID}` as const;
export const SAVANA_HARNESS_ID = "savana" as const;
export const SAVANA_SYNTHETIC_AUTH_MARKER = "savana-native-runtime" as const;

type ProviderPlugin = Parameters<OpenClawPluginApi["registerProvider"]>[0];

export const savanaProvider: ProviderPlugin = {
  id: SAVANA_PROVIDER_ID,
  label: "Savana Privacy Kernel",
  auth: [
    {
      id: "savana-native-runtime",
      label: "Savana native runtime",
      hint: "Authentication stays in the local Savana bootstrap and WebAuthn broker.",
      kind: "custom",
      run: async () => ({
        profiles: [],
        defaultModel: SAVANA_MODEL_REF,
      }),
    },
  ],
  staticCatalog: {
    order: "simple",
    run: async () => ({
      provider: {
        // If model-scoped harness selection is removed, an embedded fallback can
        // reach only the local discard port and cannot exfiltrate the prompt.
        baseUrl: "http://127.0.0.1:1",
        api: "openai-responses",
        auth: "token",
        models: [
          {
            id: SAVANA_MODEL_ID,
            name: "Savana Agent",
            api: "openai-responses",
            reasoning: false,
            input: ["text"],
            cost: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
            },
            contextWindow: 262_144,
            maxTokens: 262_144,
            agentRuntime: { id: SAVANA_HARNESS_ID },
            compat: { supportsTools: false },
          },
        ],
      },
    }),
  },
  resolveSyntheticAuth: () => ({
    apiKey: SAVANA_SYNTHETIC_AUTH_MARKER,
    source: SAVANA_SYNTHETIC_AUTH_MARKER,
    mode: "token",
  }),
  shouldDeferSyntheticProfileAuth: () => true,
};
