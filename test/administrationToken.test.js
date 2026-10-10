import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { registerAdministrationTools } from "../src/tools/administration.js";

const createHarness = ({ root, sessions = [] }) => {
  const registered = new Map();
  const auditEntries = [];
  let createCount = 0;
  const server = {
    registerTool: (name, metadata, handler) => registered.set(name, { metadata, handler })
  };
  const context = {
    config: {
      readOnly: false,
      includeRawDefault: false,
      storage: {
        secretOutputDir: root
      },
      audit: {
        recordReads: false
      }
    },
    rateLimiter: {
      check: () => ({ ok: true })
    },
    audit: {
      append: (entry) => auditEntries.push(entry)
    },
    logger: {
      generateLog: () => {},
      generateError: () => {}
    },
    technitium: {
      listSessions: async () => ({ response: { sessions } }),
      createAdminApiToken: async () => {
        createCount += 1;
        return "synthetic-created-token";
      },
      deleteSession: async () => ({ status: "ok" }),
      getCurrentSession: async () => ({ status: "ok" }),
      getPrometheusMetrics: async () => ""
    }
  };

  registerAdministrationTools({ server, context });
  return { registered, auditEntries, getCreateCount: () => createCount };
};

const writeIdentity = {
  authInfo: {
    clientId: "test-writer",
    scopes: ["write"]
  }
};

test("dns_create_api_token_file returns metadata only and writes the token to the configured directory", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "technitium-token-tool-"));
  try {
    const { registered, auditEntries } = createHarness({ root });
    const tool = registered.get("dns_create_api_token_file");
    assert.ok(tool);

    const result = await tool.handler({
      user: "homepage",
      token_name: "homepage",
      file_name: "homepage-token",
      confirm: true
    }, writeIdentity);

    assert.equal(result.structuredContent.ok, true);
    assert.equal(result.structuredContent.response.written, true);
    assert.equal(JSON.stringify(result).includes("synthetic-created-token"), false);
    assert.equal(JSON.stringify(auditEntries).includes("synthetic-created-token"), false);
    assert.equal(fs.readFileSync(path.join(root, "homepage-token"), "utf8"), "synthetic-created-token");
    assert.equal(fs.statSync(path.join(root, "homepage-token")).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("dns_create_api_token_file refuses an existing user and token-name pair before minting", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "technitium-token-tool-"));
  try {
    const { registered, getCreateCount } = createHarness({
      root,
      sessions: [{ type: "ApiToken", username: "homepage", tokenName: "homepage", partialToken: "abcd1234" }]
    });
    const tool = registered.get("dns_create_api_token_file");
    const result = await tool.handler({
      user: "homepage",
      token_name: "homepage",
      file_name: "homepage-token",
      confirm: true
    }, writeIdentity);

    assert.equal(result.structuredContent.ok, false);
    assert.equal(result.structuredContent.error.code, "resource_exists");
    assert.equal(getCreateCount(), 0);
    assert.equal(fs.existsSync(path.join(root, "homepage-token")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("API token file creation requires explicit confirmation before minting", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "technitium-token-confirm-"));
  try {
    const { registered, getCreateCount } = createHarness({ root });
    const tool = registered.get("dns_create_api_token_file");
    const result = await tool.handler({
      user: "service",
      token_name: "service",
      file_name: "service-token",
      confirm: false
    }, writeIdentity);

    assert.equal(result.structuredContent.ok, false);
    assert.equal(getCreateCount(), 0);
    assert.equal(fs.existsSync(path.join(root, "service-token")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("failed secret write after token creation never exposes the token and reports rollback uncertainty", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "technitium-token-rollback-"));
  const originalWriteFile = fs.writeFileSync;
  try {
    const { registered, getCreateCount } = createHarness({ root });
    const tool = registered.get("dns_create_api_token_file");
    fs.writeFileSync = () => {
      throw new Error("synthetic ENOSPC during one-time token publication");
    };
    const result = await tool.handler({
      user: "service",
      token_name: "service",
      file_name: "service-token",
      confirm: true
    }, writeIdentity);

    assert.equal(getCreateCount(), 1);
    assert.equal(result.structuredContent.ok, false);
    assert.match(JSON.stringify(result), /rollback could not be confirmed/i);
    assert.equal(JSON.stringify(result).includes("synthetic-created-token"), false);
    assert.equal(fs.existsSync(path.join(root, "service-token")), false);
  } finally {
    fs.writeFileSync = originalWriteFile;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
