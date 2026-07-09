import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";

const requiredEnv = {
  MCP_READ_BEARER_TOKENS: "[{name:\"reader1\",token:\"read-token\"}]",
  TECHNITIUM_BASE_URL: "https://technitium.lan:53443",
  TECHNITIUM_API_TOKEN: "api-token"
};

test("audit max entries and storage directories are configurable", () => {
  const config = loadConfig({
    env: {
      ...requiredEnv,
      AUDIT_MAX_ENTRIES: "25",
      BACKUP_DIR: "./backup-output",
      IMPORT_DIR: "./import-input"
    },
    cwd: "/tmp/mcp-technitium-config",
    requireRequired: true
  });

  assert.equal(config.audit.maxEntries, 25);
  assert.equal(config.storage.backupDir.split(String.fromCharCode(92)).join("/").endsWith("mcp-technitium-config/backup-output"), true);
  assert.equal(config.storage.importDir.split(String.fromCharCode(92)).join("/").endsWith("mcp-technitium-config/import-input"), true);
});
