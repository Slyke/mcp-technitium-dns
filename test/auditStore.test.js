import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAuditLog } from "../src/auditStore.js";

const makeConfig = ({ file, maxEntries = 0 }) => {
  return {
    audit: {
      enabled: true,
      file,
      maxEntries
    },
    redactionSecrets: ["secret-token"]
  };
};

test("audit retention keeps newest entries and redacts secrets", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-technitium-audit-"));
  const file = path.join(tmpDir, "audit.jsonl");
  const audit = createAuditLog({
    config: makeConfig({
      file,
      maxEntries: 2
    })
  });

  audit.append({
    toolName: "dns_first",
    identityName: "reader",
    action: "read",
    requestId: "request-1",
    target: {
      token: "secret-token"
    }
  });
  audit.append({
    toolName: "dns_second",
    identityName: "admin",
    action: "write",
    applied: true,
    requestId: "request-2",
    target: {}
  });
  audit.append({
    toolName: "dns_third",
    identityName: "admin",
    action: "write",
    applied: true,
    requestId: "request-3",
    target: {}
  });

  const lines = fs.readFileSync(file, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));

  assert.equal(lines.length, 2);
  assert.deepEqual(lines.map((entry) => entry.request_id), ["request-2", "request-3"]);
  assert.equal(JSON.stringify(lines).includes("secret-token"), false);
});

test("audit search filters reverse chronologically and get reads by request id", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-technitium-audit-"));
  const file = path.join(tmpDir, "audit.jsonl");
  const audit = createAuditLog({
    config: makeConfig({
      file
    })
  });

  audit.append({
    toolName: "dns_set_settings",
    identityName: "admin",
    action: "set_settings",
    applied: true,
    requestId: "request-1",
    target: {
      keys: ["forwarders"]
    }
  });
  audit.append({
    toolName: "dns_delete_zone",
    identityName: "admin",
    action: "blocked_confirmation",
    applied: false,
    ok: false,
    requestId: "request-2",
    target: {
      zone: "example.com"
    }
  });

  const results = audit.search({
    identity_name: "admin",
    ok: false,
    query: "example.com"
  });

  assert.equal(results.length, 1);
  assert.equal(results[0].request_id, "request-2");
  assert.equal(audit.get({ request_id: "request-1" }).tool_name, "dns_set_settings");
});
