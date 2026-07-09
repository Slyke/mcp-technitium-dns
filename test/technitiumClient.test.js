import assert from "node:assert/strict";
import test from "node:test";
import { createTechnitiumClient } from "../src/technitiumClient.js";

const baseConfig = {
  technitium: {
    baseUrl: "https://technitium.lan:53443",
    apiToken: "token",
    apiTokenFile: "",
    timeoutMs: 1000,
    tlsRejectUnauthorized: true,
    allowHttpLocal: false,
    allowHttpHostnames: []
  },
  redactionSecrets: ["token"]
};

const logger = {
  generateLog: () => {}
};

test("client rejects non-local http target without explicit opt-in", () => {
  assert.throws(() => {
    createTechnitiumClient({
      config: {
        ...baseConfig,
        technitium: {
          ...baseConfig.technitium,
          baseUrl: "http://example.com:5380"
        }
      },
      logger
    });
  }, /must use HTTPS/);
});

test("client allows private http target with explicit opt-in", () => {
  const client = createTechnitiumClient({
    config: {
      ...baseConfig,
      technitium: {
        ...baseConfig.technitium,
        baseUrl: "http://192.168.1.20:5380",
        allowHttpLocal: true
      }
    },
    logger
  });

  assert.equal(typeof client.getStatus, "function");
});
