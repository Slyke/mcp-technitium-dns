import fs from "node:fs";
import path from "node:path";
import { appendAudit, cleanObject, requireConfirm } from "./shared.js";

export const confirmOrAudit = ({ args, context, toolName, identity, requestId, action }) => {
  const confirmError = requireConfirm({
    args,
    action
  });

  if (confirmError) {
    appendAudit({
      context,
      toolName,
      identity,
      requestId,
      action: "blocked_confirmation",
      applied: false,
      ok: false,
      target: args
    });
  }

  return confirmError;
};

const snakeToCamel = ({ value }) => {
  return value.replace(/_([a-z])/g, (_, char) => char.toUpperCase());
};

export const toMappedParams = ({ args, map = {}, omit = [] }) => {
  const omitted = new Set(["include_raw", "confirm", ...omit]);

  return cleanObject({
    value: Object.fromEntries(
      Object.entries(args ?? {})
        .filter(([key]) => !omitted.has(key))
        .map(([key, value]) => [map[key] ?? snakeToCamel({ value: key }), Array.isArray(value) ? value.join(",") : value])
    )
  });
};

export const assertAnyLeaseIdentity = ({ args }) => {
  if (!args.hardware_address && !args.client_identifier) {
    return {
      ok: false,
      error: {
        code: "validation_error",
        message: "Either hardware_address or client_identifier is required."
      }
    };
  }

  return null;
};

export const ensureChildFile = ({ rootDir, fileName }) => {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(root, fileName);

  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error("File name resolved outside the configured storage directory.");
  }

  return resolved;
};

export const writeBufferFile = ({ directory, fileName, buffer }) => {
  fs.mkdirSync(directory, { recursive: true });
  const filePath = ensureChildFile({ rootDir: directory, fileName });
  fs.writeFileSync(filePath, buffer);
  return filePath;
};

export const backupFileName = ({ requestId }) => {
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+$/, "Z");
  return `technitium-settings-${timestamp}-${requestId.slice(0, 8)}.zip`;
};
