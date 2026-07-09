import {
  dnsCheckUpdateSchema,
  dnsGetStatsSchema,
  dnsHealthCheckSchema,
  dnsResolveSchema
} from "../validators.js";
import { publicConfigSummary } from "../config.js";
import {
  getIncludeRaw,
  makeToolHandler,
  success,
  toApiParams,
  unwrapResponse
} from "./shared.js";

const failureRate = ({ counters }) => {
  const total = Number(counters?.totalQueries ?? 0);
  const failures = Number(counters?.totalServerFailure ?? 0)
    + Number(counters?.totalRefused ?? 0)
    + Number(counters?.totalDropped ?? 0);

  return total > 0 ? failures / total : 0;
};

const forwarderSummary = ({ settings }) => {
  return {
    forwarders: settings?.forwarders ?? [],
    forwarder_protocol: settings?.forwarderProtocol,
    concurrent_forwarding: settings?.concurrentForwarding,
    forwarder_retries: settings?.forwarderRetries,
    forwarder_timeout_ms: settings?.forwarderTimeout,
    dnssec_validation: settings?.dnssecValidation,
    recursion: settings?.recursion,
    enable_blocking: settings?.enableBlocking
  };
};

export const registerDiagnosticTools = ({ server, context }) => {
  server.registerTool(
    "dns_health_check",
    {
      description: "Summarize Technitium DNS health, version, uptime, forwarder config, and lifetime failure rate.",
      inputSchema: dnsHealthCheckSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_health_check",
      handler: async ({ args, context: toolContext, requestId }) => {
        const [metricsRaw, settingsRaw, resolverRaw] = await Promise.all([
          toolContext.technitium.getMetrics({ requestId }),
          toolContext.technitium.getSettings({ requestId }),
          toolContext.technitium.healthCheck({
            query: toApiParams({
              args: {
                domain: args.domain,
                type: args.type,
                node: args.node
              }
            }),
            requestId
          })
        ]);
        const metrics = unwrapResponse({ value: metricsRaw });
        const settings = unwrapResponse({ value: settingsRaw });
        const counters = metrics?.lifetimeCounters ?? {};
        const includeRaw = getIncludeRaw({ args, config: toolContext.config });

        return {
          ok: resolverRaw?.status === "ok",
          server: resolverRaw?.server ?? settingsRaw?.server ?? metricsRaw?.server,
          version: settings?.version,
          uptime_seconds: metrics?.uptimeSeconds,
          uptimestamp: metrics?.uptimestamp ?? settings?.uptimestamp,
          failure_rate: failureRate({ counters }),
          counters,
          forwarder_config: forwarderSummary({ settings }),
          guardrails: publicConfigSummary({ config: toolContext.config }),
          ...(includeRaw
            ? {
              raw: {
                metrics: metricsRaw,
                settings: settingsRaw,
                resolver: resolverRaw
              }
            }
            : {})
        };
      }
    })
  );

  server.registerTool(
    "dns_get_stats",
    {
      description: "Get dashboard query statistics including top clients, domains, and blocked domains.",
      inputSchema: dnsGetStatsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_get_stats",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getStats({
          query: toApiParams({ args }),
          requestId
        });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_check_update",
    {
      description: "Check whether a newer Technitium DNS Server version is available.",
      inputSchema: dnsCheckUpdateSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_check_update",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.checkForUpdate({ requestId });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_resolve",
    {
      description: "Test DNS resolution through Technitium DNS Server without importing records.",
      inputSchema: dnsResolveSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_resolve",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.resolve({
          query: {
            ...toApiParams({ args }),
            import: "false"
          },
          requestId
        });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );
};
