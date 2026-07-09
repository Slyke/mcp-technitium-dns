import fs from "node:fs";
import path from "node:path";
import { sanitizeValue } from "./sanitize.js";

export const createAuditLog = ({ config }) => {
  const append = ({ toolName, identityName, action, applied = false, ok = true, target = {}, requestId }) => {
    if (!config.audit.enabled) {
      return null;
    }

    const entry = {
      timestamp: new Date().toISOString(),
      request_id: requestId,
      tool_name: toolName,
      identity_name: identityName,
      action,
      applied,
      ok,
      target: sanitizeValue({
        value: target,
        extraSecrets: config.redactionSecrets
      })
    };

    fs.mkdirSync(path.dirname(config.audit.file), { recursive: true });
    fs.appendFileSync(config.audit.file, `${JSON.stringify(entry)}\n`, "utf8");
    return entry;
  };

  return {
    append
  };
};
