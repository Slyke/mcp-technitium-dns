import fs from "node:fs";
import path from "node:path";
import { sanitizeValue } from "./sanitize.js";

const LEVELS = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

const shouldWriteLevel = ({ levels = [], level }) => {
  return levels.length === 0 || levels.includes(level);
};

const resolveGate = ({ config, loggerKey, level }) => {
  const gate = config.logging?.gates?.[loggerKey] ?? {};
  return {
    level: gate.level ?? level,
    console: gate.console,
    file: gate.file
  };
};

const renderEntry = ({ entry, format }) => {
  if (format === "text") {
    const context = entry.context ? ` ${JSON.stringify(entry.context)}` : "";
    return `${entry.timestamp} ${entry.level.toUpperCase()} ${entry.loggerKey} ${entry.message}${context}`;
  }

  return JSON.stringify(entry);
};

const writeFile = ({ sink, entry }) => {
  const filePath = path.resolve(process.cwd(), sink.path);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${renderEntry({ entry, format: sink.format })}\n`, "utf8");
};

export const createLogger = ({ config }) => {
  const sanitize = ({ value }) => {
    return sanitizeValue({
      value,
      extraSecrets: config.redactionSecrets
    });
  };

  const emit = ({ entry }) => {
    const sinks = config.logging?.sinks ?? {};
    const gate = resolveGate({
      config,
      loggerKey: entry.loggerKey,
      level: entry.level
    });
    const normalizedEntry = {
      timestamp: new Date().toISOString(),
      ...entry,
      level: gate.level
    };

    if (sinks.console?.enabled && gate.console !== false && shouldWriteLevel({ levels: sinks.console.levels ?? [], level: normalizedEntry.level })) {
      const rendered = renderEntry({
        entry: normalizedEntry,
        format: sinks.console.format
      });

      if (LEVELS[normalizedEntry.level] >= LEVELS.error) {
        console.error(rendered);
      } else {
        console.log(rendered);
      }
    }

    if (sinks.file?.enabled && gate.file !== false && shouldWriteLevel({ levels: sinks.file.levels ?? [], level: normalizedEntry.level })) {
      writeFile({
        sink: sinks.file,
        entry: normalizedEntry
      });
    }
  };

  const generateLog = (entry = {}) => {
    emit({
      entry: {
        level: entry.level ?? "info",
        caller: entry.caller,
        loggerKey: entry.loggerKey ?? "LOG",
        message: sanitize({ value: entry.message ?? "" }),
        correlationId: entry.correlationId,
        context: sanitize({ value: entry.context }),
        error: sanitize({ value: entry.error })
      }
    });
  };

  const generateError = (entry = {}) => {
    generateLog({
      level: "error",
      caller: entry.caller,
      loggerKey: entry.errorKey ?? "ERROR",
      message: sanitize({ value: entry.reason ?? "Error." }),
      correlationId: entry.correlationId,
      context: sanitize({ value: entry.context }),
      error: sanitize({ value: entry.err })
    });
  };

  const wrapError = (entry = {}) => {
    generateError(entry);
    return entry.err;
  };

  return {
    generateLog,
    generateError,
    wrapError,
    redact: sanitize
  };
};
