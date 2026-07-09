import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import pathModule from "node:path";
import { URL } from "node:url";
import { isLocalHttpHostname } from "./config.js";
import { sanitizeErrorMessage, sanitizeValue } from "./sanitize.js";

export class TechnitiumClientError extends Error {
  constructor({ message, code = "technitium_error", statusCode, path, details = {} }) {
    super(message);
    this.name = "TechnitiumClientError";
    this.code = code;
    this.statusCode = statusCode;
    this.path = path;
    this.details = details;
  }
}

const parseResponseBody = ({ text, contentType }) => {
  if (text === "") {
    return {};
  }

  if (contentType.includes("application/json") || text.trim().startsWith("{") || text.trim().startsWith("[")) {
    try {
      return JSON.parse(text);
    } catch {
      return { text };
    }
  }

  return { text };
};

const appendParams = ({ params, values }) => {
  for (const [key, value] of Object.entries(values ?? {})) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    if (Array.isArray(value)) {
      params.set(key, value.join(","));
      continue;
    }

    params.set(key, String(value));
  }
};

const makeQueryString = ({ query }) => {
  const params = new URLSearchParams();
  appendParams({ params, values: query });
  const rendered = params.toString();
  return rendered ? "?" + rendered : "";
};

const makeFormBody = ({ form }) => {
  const params = new URLSearchParams();
  appendParams({ params, values: form });
  return params.toString();
};

const makeMultipartBody = ({ fields = {}, filePath, fileFieldName = "file", fileName, contentType = "application/octet-stream" }) => {
  const boundary = "----mcp-technitium-" + crypto.randomBytes(12).toString("hex");
  const chunks = [];

  for (const [key, value] of Object.entries(fields ?? {})) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    chunks.push(Buffer.from("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + key + "\"\r\n\r\n" + String(value) + "\r\n", "utf8"));
  }

  if (filePath) {
    const resolvedFileName = fileName || pathModule.basename(filePath);
    chunks.push(Buffer.from("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fileFieldName + "\"; filename=\"" + resolvedFileName + "\"\r\nContent-Type: " + contentType + "\r\n\r\n", "utf8"));
    chunks.push(fs.readFileSync(filePath));
    chunks.push(Buffer.from("\r\n", "utf8"));
  }

  chunks.push(Buffer.from("--" + boundary + "--\r\n", "utf8"));

  return {
    boundary,
    payload: Buffer.concat(chunks)
  };
};

const isRetryableNetworkError = ({ err }) => {
  return ["ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND"].includes(err?.code);
};

const assertSafeBaseUrl = ({ baseUrl, config }) => {
  if (baseUrl.protocol === "https:") {
    return;
  }

  if (
    baseUrl.protocol === "http:"
    && config.technitium.allowHttpLocal
    && isLocalHttpHostname({
      hostname: baseUrl.hostname,
      allowedHostnames: config.technitium.allowHttpHostnames
    })
  ) {
    return;
  }

  throw new Error("TECHNITIUM_BASE_URL must use HTTPS unless TECHNITIUM_ALLOW_HTTP_LOCAL=true and the host is local/private.");
};

const createTokenProvider = ({ config }) => {
  let cachedToken = config.technitium.apiToken || "";
  let cachedMtimeMs = 0;
  let authLoadPromise = null;

  const readTokenFile = async () => {
    if (config.technitium.apiTokenFile === "") {
      return cachedToken;
    }

    const stat = fs.statSync(config.technitium.apiTokenFile);
    if (cachedToken && cachedMtimeMs === stat.mtimeMs) {
      return cachedToken;
    }

    cachedToken = fs.readFileSync(config.technitium.apiTokenFile, "utf8").trim();
    cachedMtimeMs = stat.mtimeMs;
    return cachedToken;
  };

  const getToken = async () => {
    if (cachedToken && config.technitium.apiTokenFile === "") {
      return cachedToken;
    }

    if (authLoadPromise === null) {
      authLoadPromise = readTokenFile().finally(() => {
        authLoadPromise = null;
      });
    }

    return await authLoadPromise;
  };

  return { getToken };
};

const sanitizeApiPayload = ({ payload, config }) => {
  return sanitizeValue({
    value: payload,
    extraSecrets: config.redactionSecrets
  });
};

const apiErrorFromResponse = ({ parsed, statusCode, path, config }) => {
  const apiMessage = parsed?.errorMessage ?? parsed?.message ?? parsed?.response?.errorMessage;
  const message = sanitizeErrorMessage({
    message: apiMessage || "Technitium API returned HTTP " + statusCode + ".",
    extraSecrets: config.redactionSecrets
  });
  const details = sanitizeApiPayload({
    payload: {
      status: parsed?.status,
      statusCode,
      path
    },
    config
  });

  return new TechnitiumClientError({
    message,
    statusCode,
    path,
    details
  });
};

export const createTechnitiumClient = ({ config, logger }) => {
  const baseUrl = new URL(config.technitium.baseUrl);
  assertSafeBaseUrl({ baseUrl, config });
  const tokenProvider = createTokenProvider({ config });

  const requestOnce = async ({
    method = "GET",
    path,
    query,
    form,
    json,
    multipart,
    timeoutMs,
    requestId,
    auth = "bearer",
    responseType = "json",
    sanitizeResponse = true
  }) => {
    const requestPath = path + makeQueryString({ query });
    const formPayload = form === undefined ? null : makeFormBody({ form });
    const jsonPayload = json === undefined ? null : JSON.stringify(json);
    const multipartPayload = multipart === undefined ? null : makeMultipartBody(multipart);
    const payload = multipartPayload?.payload ?? formPayload ?? jsonPayload;
    const token = auth === "bearer" ? await tokenProvider.getToken() : "";
    const headers = {
      accept: responseType === "text" ? "text/plain, application/json" : (responseType === "buffer" ? "application/octet-stream, application/zip, text/plain, application/json" : "application/json"),
      ...(token ? { authorization: "Bearer " + token } : {}),
      ...(multipartPayload ? {
        "content-type": "multipart/form-data; boundary=" + multipartPayload.boundary,
        "content-length": multipartPayload.payload.length
      } : {}),
      ...(formPayload !== null ? {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(formPayload)
      } : {}),
      ...(jsonPayload !== null ? {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(jsonPayload)
      } : {})
    };
    const requestOptions = {
      method,
      protocol: baseUrl.protocol,
      hostname: baseUrl.hostname,
      port: baseUrl.port || undefined,
      path: baseUrl.pathname.replace(/\/+$/, "") + requestPath,
      timeout: timeoutMs ?? config.technitium.timeoutMs,
      rejectUnauthorized: config.technitium.tlsRejectUnauthorized,
      headers
    };
    const transport = baseUrl.protocol === "https:" ? https : http;

    logger?.generateLog({
      level: "debug",
      caller: "technitiumClient::request",
      loggerKey: "TECHNITIUM_API_REQUEST",
      message: "Calling Technitium API.",
      correlationId: requestId,
      context: { method, path }
    });

    return await new Promise((resolve, reject) => {
      const req = transport.request(requestOptions, (res) => {
        const chunks = [];

        res.on("data", (chunk) => {
          chunks.push(chunk);
        });

        res.on("end", () => {
          const buffer = Buffer.concat(chunks);
          const text = buffer.toString("utf8");
          const contentType = String(res.headers["content-type"] ?? "");
          const parsed = responseType === "buffer"
            ? { buffer, contentType }
            : (
              responseType === "text"
                ? { text }
                : parseResponseBody({ text, contentType })
            );

          logger?.generateLog({
            level: "debug",
            caller: "technitiumClient::request",
            loggerKey: "TECHNITIUM_API_RESPONSE",
            message: "Technitium API response received.",
            correlationId: requestId,
            context: {
              method,
              path,
              statusCode: res.statusCode
            }
          });

          const statusCode = res.statusCode ?? 500;
          if (statusCode < 200 || statusCode >= 300) {
            const errorPayload = responseType === "buffer" ? parseResponseBody({ text, contentType }) : parsed;
            reject(apiErrorFromResponse({ parsed: errorPayload, statusCode, path, config }));
            return;
          }

          if (responseType === "json" && ["error", "invalid-token", "2fa-required"].includes(String(parsed?.status ?? ""))) {
            reject(apiErrorFromResponse({ parsed, statusCode, path, config }));
            return;
          }

          if (responseType === "buffer") {
            resolve(parsed);
            return;
          }

          resolve(sanitizeResponse ? sanitizeApiPayload({ payload: parsed, config }) : parsed);
        });
      });

      req.on("timeout", () => {
        req.destroy(new TechnitiumClientError({
          message: "Technitium API request timed out.",
          code: "timeout",
          path
        }));
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (payload) {
        req.write(payload);
      }

      req.end();
    });
  };

  const request = async (options) => {
    try {
      return await requestOnce(options);
    } catch (err) {
      if (options.method === "GET" && isRetryableNetworkError({ err })) {
        return await requestOnce(options);
      }

      if (err instanceof TechnitiumClientError) {
        throw err;
      }

      throw new TechnitiumClientError({
        message: sanitizeErrorMessage({
          message: err?.message ?? "Technitium API request failed.",
          extraSecrets: config.redactionSecrets
        }),
        code: err?.code === "ETIMEDOUT" ? "timeout" : "technitium_error",
        path: options.path,
        details: sanitizeApiPayload({
          payload: { causeCode: err?.code },
          config
        })
      });
    }
  };

  const get = async ({ path, query, timeoutMs, requestId, auth = "bearer", responseType = "json" }) => {
    return await request({ method: "GET", path, query, timeoutMs, requestId, auth, responseType });
  };

  const post = async ({ path, form = {}, json, multipart, timeoutMs, requestId, responseType = "json", sanitizeResponse = true }) => {
    return await request({ method: "POST", path, form: json === undefined && multipart === undefined ? form : undefined, json, multipart, timeoutMs, requestId, responseType, sanitizeResponse });
  };

  const query = async ({ path, form = {}, timeoutMs, requestId }) => {
    return await post({ path, form, timeoutMs, requestId });
  };

  const createSingleUseToken = async ({ requestId }) => {
    const raw = await post({
      path: "/api/user/createSingleUseToken",
      form: {},
      requestId,
      sanitizeResponse: false
    });

    const token = raw?.token ?? raw?.response?.token;
    if (token === undefined || token === null || token === "") {
      throw new TechnitiumClientError({
        message: "Technitium did not return a single-use token.",
        path: "/api/user/createSingleUseToken"
      });
    }

    return token;
  };

  return {
    request,
    get,
    post,
    query,
    getStatus: ({ requestId } = {}) => get({ path: "/api/status", requestId }),
    getSession: ({ requestId } = {}) => get({ path: "/api/user/session/get", requestId }),
    checkForUpdate: ({ requestId } = {}) => get({ path: "/api/user/checkForUpdate", requestId }),
    getMetrics: ({ requestId } = {}) => get({ path: "/api/dashboard/metrics/json", requestId }),
    getPrometheusMetrics: ({ requestId } = {}) => get({ path: "/api/dashboard/metrics/text", requestId, responseType: "text" }),
    getStats: ({ query: statsQuery = {}, requestId } = {}) => get({ path: "/api/dashboard/stats/get", query: statsQuery, requestId }),
    resolve: ({ query: resolveQuery = {}, requestId } = {}) => get({ path: "/api/dnsClient/resolve", query: resolveQuery, requestId }),
    healthCheck: ({ query: healthQuery = {}, requestId } = {}) => get({ path: "/api/dnsClient/healthCheck", query: healthQuery, requestId }),
    listZones: ({ query: zoneQuery = {}, requestId } = {}) => get({ path: "/api/zones/list", query: zoneQuery, requestId }),
    createZone: ({ form: zoneForm = {}, requestId }) => post({ path: "/api/zones/create", form: zoneForm, requestId }),
    deleteZone: ({ form: zoneForm = {}, requestId }) => post({ path: "/api/zones/delete", form: zoneForm, requestId }),
    enableZone: ({ form: zoneForm = {}, requestId }) => post({ path: "/api/zones/enable", form: zoneForm, requestId }),
    disableZone: ({ form: zoneForm = {}, requestId }) => post({ path: "/api/zones/disable", form: zoneForm, requestId }),
    getZoneOptions: ({ query: optionQuery = {}, requestId }) => get({ path: "/api/zones/options/get", query: optionQuery, requestId }),
    setZoneOptions: ({ form: optionForm = {}, requestId }) => post({ path: "/api/zones/options/set", form: optionForm, requestId }),
    exportZone: async ({ query: exportQuery = {}, requestId }) => {
      const token = await createSingleUseToken({ requestId });
      return await get({ path: "/api/zones/export", query: { ...exportQuery, token }, requestId, auth: "none", responseType: "text" });
    },
    getRecords: ({ query: recordsQuery = {}, requestId }) => get({ path: "/api/zones/records/get", query: recordsQuery, requestId }),
    addRecord: ({ form: recordForm = {}, requestId }) => post({ path: "/api/zones/records/add", form: recordForm, requestId }),
    updateRecord: ({ form: recordForm = {}, requestId }) => post({ path: "/api/zones/records/update", form: recordForm, requestId }),
    deleteRecord: ({ form: recordForm = {}, requestId }) => post({ path: "/api/zones/records/delete", form: recordForm, requestId }),
    signZone: ({ form = {}, requestId }) => post({ path: "/api/zones/dnssec/sign", form, requestId }),
    unsignZone: ({ form = {}, requestId }) => post({ path: "/api/zones/dnssec/unsign", form, requestId }),
    rolloverDnsKey: ({ form = {}, requestId }) => post({ path: "/api/zones/dnssec/properties/rolloverDnsKey", form, requestId }),
    listAllowed: ({ query: allowedQuery = {}, requestId }) => get({ path: "/api/allowed/list", query: allowedQuery, requestId }),
    addAllowed: ({ form: allowedForm = {}, requestId }) => post({ path: "/api/allowed/add", form: allowedForm, requestId }),
    deleteAllowed: ({ form: allowedForm = {}, requestId }) => post({ path: "/api/allowed/delete", form: allowedForm, requestId }),
    flushAllowed: ({ requestId }) => post({ path: "/api/allowed/flush", form: {}, requestId }),
    listBlocked: ({ query: blockedQuery = {}, requestId }) => get({ path: "/api/blocked/list", query: blockedQuery, requestId }),
    addBlocked: ({ form: blockedForm = {}, requestId }) => post({ path: "/api/blocked/add", form: blockedForm, requestId }),
    deleteBlocked: ({ form: blockedForm = {}, requestId }) => post({ path: "/api/blocked/delete", form: blockedForm, requestId }),
    flushBlocked: ({ requestId }) => post({ path: "/api/blocked/flush", form: {}, requestId }),
    listCache: ({ query: cacheQuery = {}, requestId }) => get({ path: "/api/cache/list", query: cacheQuery, requestId }),
    deleteCached: ({ form: cacheForm = {}, requestId }) => post({ path: "/api/cache/delete", form: cacheForm, requestId }),
    flushCache: ({ requestId }) => post({ path: "/api/cache/flush", form: {}, requestId }),
    getSettings: ({ requestId } = {}) => get({ path: "/api/settings/get", requestId }),
    setSettings: ({ settings, requestId }) => post({ path: "/api/settings/set", form: settings, requestId }),
    listTsigKeyNames: ({ query: tsigQuery = {}, requestId } = {}) => get({ path: "/api/settings/getTsigKeyNames", query: tsigQuery, requestId }),
    backupSettings: ({ query: backupQuery = {}, requestId }) => get({ path: "/api/settings/backup", query: backupQuery, requestId, responseType: "buffer" }),
    restoreSettings: ({ query: restoreQuery = {}, filePath, requestId }) => post({ path: "/api/settings/restore", multipart: { fields: restoreQuery, filePath, fileFieldName: "file", contentType: "application/zip" }, requestId }),
    forceUpdateBlockLists: ({ requestId }) => post({ path: "/api/settings/forceUpdateBlockLists", form: {}, requestId }),
    temporaryDisableBlocking: ({ form = {}, requestId }) => post({ path: "/api/settings/temporaryDisableBlocking", form, requestId }),
    listApps: ({ query: appQuery = {}, requestId } = {}) => get({ path: "/api/apps/list", query: appQuery, requestId }),
    listAppStore: ({ query: appQuery = {}, requestId } = {}) => get({ path: "/api/apps/listStoreApps", query: appQuery, requestId }),
    installApp: ({ form = {}, requestId }) => post({ path: "/api/apps/downloadAndInstall", form, requestId }),
    downloadUpdateApp: ({ form = {}, requestId }) => post({ path: "/api/apps/downloadAndUpdate", form, requestId }),
    updateApp: ({ form = {}, filePath, requestId }) => post({ path: "/api/apps/update", multipart: { fields: form, filePath, fileFieldName: "file", contentType: "application/zip" }, requestId }),
    uninstallApp: ({ form = {}, requestId }) => post({ path: "/api/apps/uninstall", form, requestId }),
    getAppConfig: ({ query: appQuery = {}, requestId }) => get({ path: "/api/apps/config/get", query: appQuery, requestId }),
    setAppConfig: ({ form = {}, requestId }) => post({ path: "/api/apps/config/set", form, requestId }),
    getDnssecProperties: ({ query: dnssecQuery = {}, requestId }) => get({ path: "/api/zones/dnssec/properties/get", query: dnssecQuery, requestId }),
    getDs: ({ query: dsQuery = {}, requestId }) => get({ path: "/api/zones/dnssec/viewDS", query: dsQuery, requestId }),
    listDhcpLeases: ({ query: leaseQuery = {}, requestId } = {}) => get({ path: "/api/dhcp/leases/list", query: leaseQuery, requestId }),
    removeDhcpLease: ({ form = {}, requestId }) => post({ path: "/api/dhcp/leases/remove", form, requestId }),
    convertDhcpLeaseToReserved: ({ form = {}, requestId }) => post({ path: "/api/dhcp/leases/convertToReserved", form, requestId }),
    convertDhcpLeaseToDynamic: ({ form = {}, requestId }) => post({ path: "/api/dhcp/leases/convertToDynamic", form, requestId }),
    listDhcpScopes: ({ query: scopeQuery = {}, requestId } = {}) => get({ path: "/api/dhcp/scopes/list", query: scopeQuery, requestId }),
    getDhcpScope: ({ query: scopeQuery = {}, requestId }) => get({ path: "/api/dhcp/scopes/get", query: scopeQuery, requestId }),
    setDhcpScope: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/set", form, requestId }),
    addDhcpReservedLease: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/addReservedLease", form, requestId }),
    removeDhcpReservedLease: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/removeReservedLease", form, requestId }),
    enableDhcpScope: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/enable", form, requestId }),
    disableDhcpScope: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/disable", form, requestId }),
    deleteDhcpScope: ({ form = {}, requestId }) => post({ path: "/api/dhcp/scopes/delete", form, requestId }),
    listSessions: ({ query: sessionQuery = {}, requestId } = {}) => get({ path: "/api/admin/sessions/list", query: sessionQuery, requestId }),
    deleteSession: ({ form = {}, requestId }) => post({ path: "/api/admin/sessions/delete", form, requestId }),
    listLogFiles: ({ query: logQuery = {}, requestId } = {}) => get({ path: "/api/logs/list", query: logQuery, requestId }),
    downloadLogFile: ({ query: logQuery = {}, requestId }) => get({ path: "/api/logs/download", query: logQuery, requestId, responseType: "text" }),
    deleteLogFile: ({ form = {}, requestId }) => post({ path: "/api/logs/delete", form, requestId }),
    deleteAllLogs: ({ form = {}, requestId }) => post({ path: "/api/logs/deleteAll", form, requestId }),
    queryLogs: ({ form: logsForm = {}, requestId }) => query({ path: "/api/logs/query", form: logsForm, requestId }),
    exportQueryLogs: ({ query: logsQuery = {}, requestId }) => get({ path: "/api/logs/export", query: logsQuery, requestId, responseType: "text" })
  };
};
