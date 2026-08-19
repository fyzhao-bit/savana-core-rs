import {
  OPENCLAW_VERSION as HOST_OPENCLAW_VERSION,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import {
  type OpenClawPluginConfigSchema,
  definePluginEntry,
} from "openclaw/plugin-sdk/plugin-entry";
import { getHealthCheck, registerHealthCheck } from "openclaw/plugin-sdk/health";

import { BridgeProcess } from "./src/bridge-process.js";
import {
  OPENCLAW_VERSION,
  ConfigError,
  parsePluginConfig,
} from "./src/config.js";
import { createSavanaHarness } from "./src/harness.js";
import {
  SAVANA_DOCTOR_CHECK_ID,
  createSavanaHealthCheck,
  runSavanaDoctor,
} from "./src/doctor.js";
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
    const doctorProbe = async () => {
      const doctorBridge = new BridgeProcess(config, { doctorOnly: true });
      try {
        await doctorBridge.start();
        return await doctorBridge.doctor();
      } finally {
        await doctorBridge.dispose();
      }
    };
    if (getHealthCheck(SAVANA_DOCTOR_CHECK_ID) === undefined) {
      registerHealthCheck(
        createSavanaHealthCheck(config, doctorProbe),
      );
    }
    api.registerCli(
      ({ program }) => {
        const savana = program
          .command("savana")
          .description("Operate the Savana privacy runtime");
        savana
          .command("doctor")
          .description("Run the fail-closed Savana runtime preflight")
          .option("--json", "Emit machine-readable JSON")
          .action(async (options: { json?: boolean }) => {
            const findings = await runSavanaDoctor(api.config, config, doctorProbe);
            const report = {
              ok: findings.length === 0,
              checkId: SAVANA_DOCTOR_CHECK_ID,
              findings,
            };
            if (options.json === true) {
              process.stdout.write(`${JSON.stringify(report)}\n`);
            } else if (report.ok) {
              process.stdout.write("Savana runtime preflight passed.\n");
            } else {
              for (const finding of findings) {
                process.stderr.write(
                  `Savana preflight: ${finding.requirement ?? finding.checkId}: ${finding.message}\n`,
                );
              }
            }
            process.exitCode = report.ok ? 0 : 1;
          });
      },
      {
        descriptors: [
          {
            name: "savana",
            description: "Operate the Savana privacy runtime",
            hasSubcommands: true,
          },
        ],
      },
    );
    api.registerProvider(savanaProvider);
    api.registerAgentHarness(createSavanaHarness(bridge));
  },
});
