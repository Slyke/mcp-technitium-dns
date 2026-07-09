import assert from "node:assert/strict";
import test from "node:test";
import { sanitizeErrorMessage, sanitizeValue } from "../src/sanitize.js";

test("sanitizer redacts tokens passwords stack traces and sensitive paths", () => {
  const sanitized = sanitizeValue({
    value: {
      token: "secret-token",
      nested: {
        password: "secret-pass",
        stackTrace: "at /home/user/app/file.js:1",
        certificatePath: "/home/user/cert.pfx"
      },
      message: "Bearer secret-token failed at /home/user/app/file.js"
    },
    extraSecrets: ["secret-token"]
  });

  assert.equal(sanitized.token, "[REDACTED]");
  assert.equal(sanitized.nested.password, "[REDACTED]");
  assert.equal("stackTrace" in sanitized.nested, false);
  assert.equal(sanitized.nested.certificatePath, "[REDACTED_PATH]");
  assert.match(sanitized.message, /Bearer \[REDACTED\]/);
  assert.doesNotMatch(sanitized.message, /\/home\/user/);
});

test("error message sanitizer strips stack-like text and paths", () => {
  const message = sanitizeErrorMessage({
    message: "failed at /home/user/app/file.js\n at stack frame",
    extraSecrets: []
  });

  assert.doesNotMatch(message, /\/home\/user/);
  assert.doesNotMatch(message, /stack frame/);
});
