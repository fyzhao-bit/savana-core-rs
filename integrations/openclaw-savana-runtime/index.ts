import {
  OPENCLAW_VERSION as HOST_OPENCLAW_VERSION,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  type OpenClawPluginConfigSchema,
  definePluginEntry,
} from "openclaw/plugin-sdk/plugin-entry";

import { BridgeProcess } from "./src/bridge-process.js";
import {
  OPENCLAW_VERSION,
  ConfigError,
  parsePluginConfig,
} from "./src/config.js";
import { createSavanaHarness } from "./src/harness.js";
import { savanaProvider } from "./src/provider.js";

const configSchema: OpenClawPluginConfigSchema = {
  validate(value) {
    try {
      return { ok: true, value: parsePluginConfig(value) };
    } catch (error) {
      if (error instanceof ConfigError) {
        return { ok: false, errors: [error.message] };
      }
      return { ok: false, errors: ["invalid Savana plugin configuration"] };
    }
  },
};

export default definePluginEntry({
  id: "savana",
  name: "Savana Privacy Runtime",
  description: "Routes selected OpenClaw turns through the Savana privacy kernel.",
  configSchema,
  register(api) {
    if (HOST_OPENCLAW_VERSION !== OPENCLAW_VERSION) {
      throw new Error("Savana OpenClaw compatibility mismatch");
    }
    const config = parsePluginConfig(api.pluginConfig);
    const bridge = new BridgeProcess(config, {
      diagnostic: (code) => api.logger.warn(`savana runtime: ${code}`),
    });
    api.registerProvider(savanaProvider);
    api.registerAgentHarness(createSavanaHarness(bridge));
  },
});
