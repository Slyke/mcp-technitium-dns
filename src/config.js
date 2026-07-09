import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import JSON5 from "json5";

const DEFAULT_CONFIG_FILE = "./config.json5";
const DEFAULT_AUDIT_FILE = "./data/audit.jsonl";
const DEFAULT_CERTS_DIR = "./data/certs";
const DEFAULT_BACKUP_DIR = "./data/backups";
const DEFAULT_IMPORT_DIR = "./data/imports";

const parseBoolean = ({ value, fallback = false }) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  if (typeof value === "boolean") {
    return value;
  }

  return ["1", "true", "yes", "y", "on"].includes(String(value).trim().toLowerCase());
};

const parseNumber = ({ value, fallback, min, max }) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  const boundedMin = min === undefined ? parsed : Math.max(parsed, min);
  return max === undefined ? boundedMin : Math.min(boundedMin, max);
};

const parseList = ({ value }) => {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }

  if (value === undefined || value === null || value === "") {
    return [];
  }

  const raw = String(value).trim();

  if (raw.startsWith("[") || raw.startsWith("{")) {
    return parseList({
      value: JSON5.parse(raw)
    });
  }

  return raw.split(",").map((item) => item.trim()).filter(Boolean);
};

const readJson5File = ({ filePath }) => {
  if (!filePath || !fs.existsSync(filePath)) {
    return {};
  }

  return JSON5.parse(fs.readFileSync(filePath, "utf8"));
};

const readSecretFile = ({ filePath, cwd }) => {
  if (!filePath) {
    return "";
  }

  const resolved = path.resolve(cwd, String(filePath));
  return fs.readFileSync(resolved, "utf8").trim();
};

const hasOwn = ({ obj, key }) => {
  return Object.prototype.hasOwnProperty.call(obj ?? {}, key);
};

const envOrConfig = ({ env, config, envKey, configPath, fallback }) => {
  if (env[envKey] !== undefined) {
    return env[envKey];
  }

  const parts = configPath.split(".");
  let current = config;

  for (const part of parts) {
    if (!hasOwn({ obj: current, key: part })) {
      return fallback;
    }

    current = current[part];
  }

  return current ?? fallback;
};

const parseTokenEntries = ({ value, label, cwd }) => {
  const parsed = typeof value === "string" ? JSON5.parse(value) : value;

  if (!Array.isArray(parsed)) {
    throw new Error(`${label} must be an array of { name, token } or { name, tokenFile } objects.`);
  }

  return parsed.map((entry, index) => {
    const name = String(entry?.name ?? "").trim();
    const token = String(entry?.token ?? readSecretFile({
      filePath: entry?.tokenFile,
      cwd
    }) ?? "");

    if (!name || !token) {
      throw new Error(`${label}[${index}] must include non-empty name and token/tokenFile fields.`);
    }

    return {
      name,
      token
    };
  });
};

const resolveTokenEntries = ({ env, config, envKey, configPath, cwd }) => {
  const fileValue = envOrConfig({
    env,
    config,
    envKey: `${envKey}_FILE`,
    configPath: `${configPath}File`,
    fallback: undefined
  });

  if (fileValue) {
    return parseTokenEntries({
      value: readJson5File({
        filePath: path.resolve(cwd, String(fileValue))
      }),
      label: `${envKey}_FILE`,
      cwd
    });
  }

  const rawValue = envOrConfig({
    env,
    config,
    envKey,
    configPath,
    fallback: undefined
  });

  if (rawValue === undefined) {
    return [];
  }

  return parseTokenEntries({
    value: rawValue,
    label: envKey,
    cwd
  });
};

const resolveLogging = ({ config }) => {
  return config.logging ?? {
    sinks: {
      console: {
        enabled: true,
        format: "json",
        levels: ["info", "warn", "error"]
      },
      file: {
        enabled: false,
        format: "json",
        path: "./logs/app.jsonl",
        levels: ["warn", "error"]
      }
    },
    gates: {
      SERVICE_BOOT_DIAGNOSTICS: {
        level: "info",
        console: true
      },
      MCP_TOOL_CALL: {
        level: "info",
        console: true
      },
      MCP_AUDIT_APPEND_FAILED: {
        level: "warn",
        console: true
      },
      RATE_LIMIT_BLOCKED: {
        level: "warn",
        console: true
      },
      TECHNITIUM_API_REQUEST: {
        level: "debug",
        console: false
      },
      TECHNITIUM_API_RESPONSE: {
        level: "debug",
        console: false
      }
    }
  };
};

const isPrivateIpv4 = ({ address }) => {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }

  return parts[0] === 10
    || parts[0] === 127
    || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    || (parts[0] === 192 && parts[1] === 168)
    || (parts[0] === 169 && parts[1] === 254);
};

export const isLocalHttpHostname = ({ hostname, allowedHostnames = [] }) => {
  const normalized = String(hostname ?? "").toLowerCase();

  if (allowedHostnames.map((item) => String(item).toLowerCase()).includes(normalized)) {
    return true;
  }

  if (["localhost", "::1", "[::1]"].includes(normalized)) {
    return true;
  }

  if (net.isIP(normalized) === 4) {
    return isPrivateIpv4({ address: normalized });
  }

  if (net.isIP(normalized) === 6) {
    return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
  }

  return !normalized.includes(".")
    || normalized.endsWith(".lan")
    || normalized.endsWith(".local")
    || normalized.endsWith(".home.arpa");
};

const resolveTechnitiumToken = ({ env, fileConfig, cwd }) => {
  const apiToken = String(envOrConfig({
    env,
    config: fileConfig,
    envKey: "TECHNITIUM_API_TOKEN",
    configPath: "technitium.apiToken",
    fallback: ""
  }) ?? "");
  const apiTokenFile = String(envOrConfig({
    env,
    config: fileConfig,
    envKey: "TECHNITIUM_API_TOKEN_FILE",
    configPath: "technitium.apiTokenFile",
    fallback: ""
  }) ?? "");

  return {
    apiToken,
    apiTokenFile: apiTokenFile ? path.resolve(cwd, apiTokenFile) : ""
  };
};

export const loadConfig = ({
  env = process.env,
  cwd = process.cwd(),
  requireRequired = true
} = {}) => {
  const configFile = env.CONFIG_FILE ?? DEFAULT_CONFIG_FILE;
  const configPath = path.resolve(cwd, configFile);
  const fileConfig = readJson5File({ filePath: configPath });
  const httpEnabled = parseBoolean({
    value: envOrConfig({ env, config: fileConfig, envKey: "HTTP_ENABLED", configPath: "http.enabled", fallback: false }),
    fallback: false
  });
  const httpsEnabled = parseBoolean({
    value: envOrConfig({ env, config: fileConfig, envKey: "HTTPS_ENABLED", configPath: "https.enabled", fallback: true }),
    fallback: true
  });
  const readOnly = parseBoolean({
    value: envOrConfig({ env, config: fileConfig, envKey: "READ_ONLY", configPath: "readOnly", fallback: false }),
    fallback: false
  });

  if (!httpEnabled && !httpsEnabled) {
    throw new Error("At least one of HTTP_ENABLED or HTTPS_ENABLED must be true.");
  }

  const readTokens = resolveTokenEntries({
    env,
    config: fileConfig,
    envKey: "MCP_READ_BEARER_TOKENS",
    configPath: "auth.readBearerTokens",
    cwd
  });
  const readWriteTokens = readOnly
    ? []
    : resolveTokenEntries({
      env,
      config: fileConfig,
      envKey: "MCP_READWRITE_BEARER_TOKENS",
      configPath: "auth.readWriteBearerTokens",
      cwd
    });
  const technitiumToken = resolveTechnitiumToken({
    env,
    fileConfig,
    cwd
  });
  const requiredValues = {
    TECHNITIUM_BASE_URL: envOrConfig({
      env,
      config: fileConfig,
      envKey: "TECHNITIUM_BASE_URL",
      configPath: "technitium.baseUrl",
      fallback: ""
    }),
    TECHNITIUM_API_TOKEN: technitiumToken.apiToken || technitiumToken.apiTokenFile
  };

  if (requireRequired) {
    const missing = Object.entries(requiredValues)
      .filter(([, value]) => !value)
      .map(([key]) => key);

    if (readTokens.length === 0 && readWriteTokens.length === 0) {
      missing.push("MCP_READ_BEARER_TOKENS or MCP_READWRITE_BEARER_TOKENS");
    }

    if (missing.length > 0) {
      throw new Error(`Missing required configuration: ${missing.join(", ")}`);
    }
  }

  const technitiumBaseUrl = String(requiredValues.TECHNITIUM_BASE_URL ?? "").replace(/\/+$/, "");
  const allowHttpHostnames = parseList({
    value: envOrConfig({
      env,
      config: fileConfig,
      envKey: "TECHNITIUM_ALLOW_HTTP_HOSTNAMES",
      configPath: "technitium.allowHttpHostnames",
      fallback: []
    })
  });

  return {
    configPath,
    http: {
      enabled: httpEnabled,
      host: String(envOrConfig({ env, config: fileConfig, envKey: "HTTP_HOST", configPath: "http.host", fallback: "0.0.0.0" })),
      port: parseNumber({
        value: envOrConfig({ env, config: fileConfig, envKey: "HTTP_PORT", configPath: "http.port", fallback: 3000 }),
        fallback: 3000,
        min: 1,
        max: 65535
      })
    },
    https: {
      enabled: httpsEnabled,
      host: String(envOrConfig({ env, config: fileConfig, envKey: "HTTPS_HOST", configPath: "https.host", fallback: "0.0.0.0" })),
      port: parseNumber({
        value: envOrConfig({ env, config: fileConfig, envKey: "HTTPS_PORT", configPath: "https.port", fallback: 3443 }),
        fallback: 3443,
        min: 1,
        max: 65535
      })
    },
    auth: {
      readTokens,
      readWriteTokens,
      authHealthchecks: parseBoolean({
        value: envOrConfig({
          env,
          config: fileConfig,
          envKey: "AUTH_HEALTHCHECKS",
          configPath: "auth.healthchecks",
          fallback: false
        })
      })
    },
    technitium: {
      baseUrl: technitiumBaseUrl,
      apiToken: technitiumToken.apiToken,
      apiTokenFile: technitiumToken.apiTokenFile,
      timeoutMs: parseNumber({
        value: envOrConfig({
          env,
          config: fileConfig,
          envKey: "TECHNITIUM_TIMEOUT_MS",
          configPath: "technitium.timeoutMs",
          fallback: 10000
        }),
        fallback: 10000,
        min: 1000,
        max: 120000
      }),
      tlsRejectUnauthorized: parseBoolean({
        value: envOrConfig({
          env,
          config: fileConfig,
          envKey: "TECHNITIUM_TLS_REJECT_UNAUTHORIZED",
          configPath: "technitium.tlsRejectUnauthorized",
          fallback: true
        }),
        fallback: true
      }),
      allowHttpLocal: parseBoolean({
        value: envOrConfig({
          env,
          config: fileConfig,
          envKey: "TECHNITIUM_ALLOW_HTTP_LOCAL",
          configPath: "technitium.allowHttpLocal",
          fallback: false
        }),
        fallback: false
      }),
      allowHttpHostnames
    },
    audit: {
      enabled: parseBoolean({
        value: envOrConfig({ env, config: fileConfig, envKey: "AUDIT_ENABLED", configPath: "audit.enabled", fallback: true }),
        fallback: true
      }),
      recordReads: parseBoolean({
        value: envOrConfig({ env, config: fileConfig, envKey: "AUDIT_RECORD_READS", configPath: "audit.recordReads", fallback: false }),
        fallback: false
      }),
      maxEntries: parseNumber({
        value: envOrConfig({ env, config: fileConfig, envKey: "AUDIT_MAX_ENTRIES", configPath: "audit.maxEntries", fallback: 0 }),
        fallback: 0,
        min: 0,
        max: 1000000
      }),
      file: path.resolve(cwd, String(envOrConfig({
        env,
        config: fileConfig,
        envKey: "AUDIT_FILE",
        configPath: "audit.file",
        fallback: DEFAULT_AUDIT_FILE
      })))
    },
    rateLimits: {
      read: {
        enabled: true,
        max: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_READ_MAX", configPath: "rateLimits.read.max", fallback: 120 }), fallback: 120, min: 1, max: 10000 }),
        windowMs: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_READ_WINDOW_MS", configPath: "rateLimits.read.windowMs", fallback: 60000 }), fallback: 60000, min: 1000, max: 3600000 })
      },
      write: {
        enabled: true,
        max: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_WRITE_MAX", configPath: "rateLimits.write.max", fallback: 30 }), fallback: 30, min: 1, max: 10000 }),
        windowMs: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_WRITE_WINDOW_MS", configPath: "rateLimits.write.windowMs", fallback: 60000 }), fallback: 60000, min: 1000, max: 3600000 })
      },
      destructive: {
        enabled: true,
        max: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_DESTRUCTIVE_MAX", configPath: "rateLimits.destructive.max", fallback: 5 }), fallback: 5, min: 1, max: 10000 }),
        windowMs: parseNumber({ value: envOrConfig({ env, config: fileConfig, envKey: "RATE_LIMIT_DESTRUCTIVE_WINDOW_MS", configPath: "rateLimits.destructive.windowMs", fallback: 60000 }), fallback: 60000, min: 1000, max: 3600000 })
      }
    },
    readOnly,
    includeRawDefault: parseBoolean({
      value: envOrConfig({
        env,
        config: fileConfig,
        envKey: "INCLUDE_RAW_DEFAULT",
        configPath: "includeRawDefault",
        fallback: false
      })
    }),
    certsDir: path.resolve(cwd, String(envOrConfig({
      env,
      config: fileConfig,
      envKey: "CERTS_DIR",
      configPath: "certsDir",
      fallback: DEFAULT_CERTS_DIR
    }))),
    storage: {
      backupDir: path.resolve(cwd, String(envOrConfig({
        env,
        config: fileConfig,
        envKey: "BACKUP_DIR",
        configPath: "storage.backupDir",
        fallback: DEFAULT_BACKUP_DIR
      }))),
      importDir: path.resolve(cwd, String(envOrConfig({
        env,
        config: fileConfig,
        envKey: "IMPORT_DIR",
        configPath: "storage.importDir",
        fallback: DEFAULT_IMPORT_DIR
      })))
    },
    readyCheckTechnitium: parseBoolean({
      value: envOrConfig({
        env,
        config: fileConfig,
        envKey: "READY_CHECK_TECHNITIUM",
        configPath: "readyCheckTechnitium",
        fallback: false
      })
    }),
    logging: resolveLogging({ config: fileConfig }),
    redactionSecrets: [
      technitiumToken.apiToken,
      ...readTokens.map((entry) => entry.token),
      ...readWriteTokens.map((entry) => entry.token)
    ].filter(Boolean)
  };
};

export const publicConfigSummary = ({ config }) => {
  let technitiumHost = "";
  let technitiumProtocol = "";

  try {
    const url = new URL(config.technitium.baseUrl);
    technitiumHost = url.hostname;
    technitiumProtocol = url.protocol.replace(":", "");
  } catch {
    technitiumHost = "";
    technitiumProtocol = "";
  }

  return {
    read_only: config.readOnly,
    technitium_host: technitiumHost,
    technitium_protocol: technitiumProtocol,
    target_http_local_opt_in: config.technitium.allowHttpLocal,
    mcp_https_enabled: config.https.enabled,
    mcp_http_enabled: config.http.enabled
  };
};
