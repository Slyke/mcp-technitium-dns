import fs from "node:fs";
import path from "node:path";
import { sanitizeValue } from "./sanitize.js";

const readEntries = ({ file }) => {
  if (!fs.existsSync(file)) {
    return [];
  }

  return fs.readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
};

const writeEntries = ({ file, entries }) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = entries.map((entry) => JSON.stringify(entry)).join("\n");
  fs.writeFileSync(file, body ? `${body}\n` : "", "utf8");
};

const applyRetention = ({ config }) => {
  if (!config.audit.maxEntries || config.audit.maxEntries < 1 || !fs.existsSync(config.audit.file)) {
    return;
  }

  const entries = readEntries({ file: config.audit.file });
  if (entries.length <= config.audit.maxEntries) {
    return;
  }

  writeEntries({
    file: config.audit.file,
    entries: entries.slice(-config.audit.maxEntries)
  });
};

const matchesFilters = ({ entry, filters }) => {
  const timestamp = Date.parse(entry.timestamp ?? "");
  const fromTime = filters.from ? Date.parse(filters.from) : null;
  const toTime = filters.to ? Date.parse(filters.to) : null;
  const normalizedQuery = String(filters.query ?? "").trim().toLowerCase();

  if (filters.tool_name && entry.tool_name !== filters.tool_name) return false;
  if (filters.identity_name && entry.identity_name !== filters.identity_name) return false;
  if (filters.action && entry.action !== filters.action) return false;
  if (filters.request_id && entry.request_id !== filters.request_id) return false;
  if (filters.applied !== undefined && entry.applied !== filters.applied) return false;
  if (filters.ok !== undefined && entry.ok !== filters.ok) return false;
  if (fromTime && (!Number.isFinite(timestamp) || timestamp < fromTime)) return false;
  if (toTime && (!Number.isFinite(timestamp) || timestamp > toTime)) return false;
  if (!normalizedQuery) return true;

  return JSON.stringify(entry).toLowerCase().includes(normalizedQuery);
};

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
    applyRetention({ config });
    return entry;
  };

  const search = ({ limit = 100, offset = 0, ...filters } = {}) => {
    return readEntries({ file: config.audit.file })
      .reverse()
      .filter((entry) => matchesFilters({ entry, filters }))
      .slice(offset, offset + limit);
  };

  const get = ({ request_id }) => {
    return readEntries({ file: config.audit.file }).find((entry) => entry.request_id === request_id) ?? null;
  };

  return {
    append,
    search,
    get
  };
};
