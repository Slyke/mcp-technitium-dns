import {
  dnsDnssecInfoSchema,
  dnsGetAppConfigSchema,
  dnsGetSettingsSchema,
  dnsInstallAppSchema,
  dnsListAppsSchema,
  dnsQueryLogsSchema,
  dnsSetSettingsSchema,
  dnsTempDisableBlockingSchema,
  dnsUninstallAppSchema
} from "../validators.js";
import {
  appendAudit,
  getIncludeRaw,
  makeToolHandler,
  requireConfirm,
  success,
  toApiParams,
  unwrapResponse
} from "./shared.js";

const confirmOrAudit = ({ args, context, toolName, identity, requestId, action }) => {
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

export const registerSettingsAppsLogsDnssecTools = ({ server, context }) => {
  server.registerTool(
    "dns_get_settings",
    {
      description: "Get full Technitium DNS Server settings with sensitive fields sanitized.",
      inputSchema: dnsGetSettingsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_get_settings",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getSettings({ requestId });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_query_logs",
    {
      description: "Query Technitium DNS app logs with filters for client IP, protocol, response type, rcode, qname, qtype, and qclass.",
      inputSchema: dnsQueryLogsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_query_logs",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.queryLogs({
          form: toApiParams({ args }),
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
    "dns_list_apps",
    {
      description: "List installed Technitium DNS apps.",
      inputSchema: dnsListAppsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_apps",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listApps({ query: toApiParams({ args }), requestId });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_list_app_store",
    {
      description: "List apps available from the Technitium DNS app store.",
      inputSchema: dnsListAppsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_app_store",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listAppStore({ query: toApiParams({ args }), requestId });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_get_app_config",
    {
      description: "Get configuration for an installed Technitium DNS app.",
      inputSchema: dnsGetAppConfigSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_get_app_config",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getAppConfig({
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
    "dns_dnssec_info",
    {
      description: "Get DNSSEC properties for a signed or unsigned primary zone.",
      inputSchema: dnsDnssecInfoSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dnssec_info",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getDnssecProperties({
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
    "dns_get_ds",
    {
      description: "Get DS records for a DNSSEC-signed primary zone.",
      inputSchema: dnsDnssecInfoSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_get_ds",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getDs({
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

  if (!context.config.readOnly) {
    server.registerTool(
      "dns_set_settings",
      {
        description: "Update Technitium DNS Server settings by POSTing only the provided validated setting keys.",
        inputSchema: dnsSetSettingsSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_set_settings",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.setSettings({
            settings: args.settings,
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_set_settings",
            identity,
            requestId,
            action: "set_settings",
            applied: true,
            ok: true,
            target: {
              keys: Object.keys(args.settings),
              merge_existing: false
            }
          });

          return success({
            response: unwrapResponse({ value: raw }),
            raw
          });
        }
      })
    );

    server.registerTool(
      "dns_update_blocklists",
      {
        description: "Force immediate Technitium block-list update.",
        inputSchema: dnsListAppsSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_update_blocklists",
        mutating: true,
        handler: async ({ context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.forceUpdateBlockLists({ requestId });

          appendAudit({
            context: toolContext,
            toolName: "dns_update_blocklists",
            identity,
            requestId,
            action: "update_blocklists",
            applied: true,
            ok: true,
            target: {}
          });

          return success({
            response: unwrapResponse({ value: raw }),
            raw
          });
        }
      })
    );

    server.registerTool(
      "dns_temp_disable_blocking",
      {
        description: "Temporarily disable Technitium blocking. Blocking auto re-enables after the requested minutes.",
        inputSchema: dnsTempDisableBlockingSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_temp_disable_blocking",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.temporaryDisableBlocking({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_temp_disable_blocking",
            identity,
            requestId,
            action: "temporary_disable_blocking",
            applied: true,
            ok: true,
            target: {
              minutes: args.minutes
            }
          });

          return success({
            response: unwrapResponse({ value: raw }),
            raw
          });
        }
      })
    );

    server.registerTool(
      "dns_install_app",
      {
        description: "Install a Technitium DNS app by name and HTTPS app-store/download URL.",
        inputSchema: dnsInstallAppSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_install_app",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.installApp({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_install_app",
            identity,
            requestId,
            action: "install_app",
            applied: true,
            ok: true,
            target: {
              name: args.name,
              url: args.url
            }
          });

          return success({
            response: unwrapResponse({ value: raw }),
            raw
          });
        }
      })
    );

    server.registerTool(
      "dns_uninstall_app",
      {
        description: "Uninstall a Technitium DNS app. Requires confirm: true.",
        inputSchema: dnsUninstallAppSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_uninstall_app",
        mutating: true,
        destructive: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const confirmError = confirmOrAudit({
            args,
            context: toolContext,
            toolName: "dns_uninstall_app",
            identity,
            requestId,
            action: "uninstall app"
          });
          if (confirmError) {
            return confirmError;
          }

          const raw = await toolContext.technitium.uninstallApp({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_uninstall_app",
            identity,
            requestId,
            action: "uninstall_app",
            applied: true,
            ok: true,
            target: {
              name: args.name
            }
          });

          return success({
            response: unwrapResponse({ value: raw }),
            raw
          });
        }
      })
    );
  }
};
