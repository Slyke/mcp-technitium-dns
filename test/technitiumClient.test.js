import assert from "node:assert/strict";
import http from "node:http";
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

test("client keeps a created API token internal and sends the documented form fields", async () => {
  const requests = [];
  const logContexts = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      requests.push({
        method: req.method,
        url: req.url,
        body: Buffer.concat(chunks).toString("utf8")
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        response: {
          token: "synthetic-created-token"
        }
      }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const client = createTechnitiumClient({
      config: {
        ...baseConfig,
        technitium: {
          ...baseConfig.technitium,
          baseUrl: `http://127.0.0.1:${address.port}`,
          allowHttpLocal: true
        }
      },
      logger: {
        generateLog: (entry) => logContexts.push(entry)
      }
    });

    const token = await client.createAdminApiToken({
      form: {
        user: "homepage",
        tokenName: "homepage"
      },
      requestId: "test-request"
    });

    assert.equal(token, "synthetic-created-token");
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url, "/api/admin/sessions/createToken");
    const body = new URLSearchParams(requests[0].body);
    assert.equal(body.get("user"), "homepage");
    assert.equal(body.get("tokenName"), "homepage");
    assert.equal(JSON.stringify(logContexts).includes("synthetic-created-token"), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
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
