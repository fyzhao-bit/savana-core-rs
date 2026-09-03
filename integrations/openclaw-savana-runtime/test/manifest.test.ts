import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

interface Manifest {
  readonly commandAliases?: readonly {
    readonly name: string;
    readonly kind: string;
  }[];
  readonly activation?: {
    readonly onStartup?: boolean;
    readonly onCommands?: readonly string[];
  };
}

const manifest = JSON.parse(
  readFileSync(new URL("../openclaw.plugin.json", import.meta.url), "utf8"),
) as Manifest;

describe("OpenClaw manifest activation", () => {
  it("loads the plugin for its Savana operator command", () => {
    expect(manifest.activation?.onCommands ?? []).toContain("savana");
    expect(manifest.commandAliases).toContainEqual({ name: "savana", kind: "cli" });
  });

  it("loads the Savana harness during Gateway startup", () => {
    expect(manifest.activation?.onStartup).toBe(true);
  });
});
