import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { isLocalHttpHostname, loadConfig } from "../src/config.js";

const requiredEnv = {
  MCP_READ_BEARER_TOKENS: "[{name:\"reader1\",token:\"read-token\"}]",
  TECHNITIUM_BASE_URL: "https://technitium.lan:53443",
  TECHNITIUM_API_TOKEN: "api-token"
};

test("https is enabled by default and http is disabled by default", () => {
  const config = loadConfig({
    env: requiredEnv,
    cwd: "/tmp",
    requireRequired: true
  });

  assert.equal(config.https.enabled, true);
  assert.equal(config.http.enabled, false);
});

test("read-only mode drops readwrite bearer tokens", () => {
  const config = loadConfig({
    env: {
      ...requiredEnv,
      READ_ONLY: "true",
      MCP_READWRITE_BEARER_TOKENS: "[{name:\"admin\",token:\"admin-token\"}]"
    },
    cwd: "/tmp",
    requireRequired: true
  });

  assert.equal(config.readOnly, true);
  assert.equal(config.auth.readWriteTokens.length, 0);
});

test("technitium api token can be loaded from a file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-technitium-"));
  const tokenFile = path.join(tmpDir, "technitium.token");
  fs.writeFileSync(tokenFile, "file-token\n", "utf8");

  const config = loadConfig({
    env: {
      MCP_READ_BEARER_TOKENS: "[{name:\"reader1\",token:\"read-token\"}]",
      TECHNITIUM_BASE_URL: "https://technitium.lan:53443",
      TECHNITIUM_API_TOKEN_FILE: tokenFile
    },
    cwd: tmpDir,
    requireRequired: true
  });

  assert.equal(config.technitium.apiToken, "");
  assert.equal(config.technitium.apiTokenFile, tokenFile);
});

test("local http hostname classifier allows private/local names only", () => {
  assert.equal(isLocalHttpHostname({ hostname: "192.168.1.10" }), true);
  assert.equal(isLocalHttpHostname({ hostname: "technitium.lan" }), true);
  assert.equal(isLocalHttpHostname({ hostname: "example.com" }), false);
});
