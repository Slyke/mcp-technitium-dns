import {
  dnsDeleteCachedSchema,
  domainMutationSchema,
  flushConfirmSchema,
  hierarchicalListSchema
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

const confirmFlush = ({ args, context, toolName, identity, requestId, action }) => {
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

const listTool = ({ server, context, name, description, clientMethod }) => {
  server.registerTool(
    name,
    {
      description,
      inputSchema: hierarchicalListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: name,
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium[clientMethod]({
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
};

const domainWriteTool = ({ server, context, name, description, clientMethod, action }) => {
  server.registerTool(
    name,
    {
      description,
      inputSchema: domainMutationSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: name,
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium[clientMethod]({
          form: toApiParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: name,
          identity,
          requestId,
          action,
          applied: true,
          ok: true,
          target: {
            domain: args.domain
          }
        });

        return success({
          response: unwrapResponse({ value: raw }),
          raw
        });
      }
    })
  );
};

const flushTool = ({ server, context, name, description, clientMethod, action, actionLabel }) => {
  server.registerTool(
    name,
    {
      description,
      inputSchema: flushConfirmSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: name,
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmFlush({
          args,
          context: toolContext,
          toolName: name,
          identity,
          requestId,
          action: actionLabel
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium[clientMethod]({
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: name,
          identity,
          requestId,
          action,
          applied: true,
          ok: true,
          target: {
            scope: "all"
          }
        });

        return success({
          response: unwrapResponse({ value: raw }),
          raw
        });
      }
    })
  );
};

export const registerBlockingCacheTools = ({ server, context }) => {
  listTool({
    server,
    context,
    name: "dns_list_blocked",
    description: "List blocked domains hierarchically with drill-down support.",
    clientMethod: "listBlocked"
  });

  listTool({
    server,
    context,
    name: "dns_list_allowed",
    description: "List allowed domains hierarchically with drill-down support.",
    clientMethod: "listAllowed"
  });

  listTool({
    server,
    context,
    name: "dns_list_cache",
    description: "List DNS cache zones and records hierarchically with drill-down support.",
    clientMethod: "listCache"
  });

  if (!context.config.readOnly) {
    domainWriteTool({
      server,
      context,
      name: "dns_block_domain",
      description: "Add a domain to the custom blocked domains list.",
      clientMethod: "addBlocked",
      action: "block_domain"
    });

    domainWriteTool({
      server,
      context,
      name: "dns_remove_blocked",
      description: "Remove a domain from the custom blocked domains list.",
      clientMethod: "deleteBlocked",
      action: "remove_blocked_domain"
    });

    flushTool({
      server,
      context,
      name: "dns_flush_blocked",
      description: "Flush the entire custom blocked domains list. Requires confirm: true.",
      clientMethod: "flushBlocked",
      action: "flush_blocked",
      actionLabel: "flush blocked domains"
    });

    domainWriteTool({
      server,
      context,
      name: "dns_allow_domain",
      description: "Add a domain to the allowed domains list to bypass block lists.",
      clientMethod: "addAllowed",
      action: "allow_domain"
    });

    domainWriteTool({
      server,
      context,
      name: "dns_remove_allowed",
      description: "Remove a domain from the allowed domains list.",
      clientMethod: "deleteAllowed",
      action: "remove_allowed_domain"
    });

    flushTool({
      server,
      context,
      name: "dns_flush_allowed",
      description: "Flush the entire allowed domains list. Requires confirm: true.",
      clientMethod: "flushAllowed",
      action: "flush_allowed",
      actionLabel: "flush allowed domains"
    });

    flushTool({
      server,
      context,
      name: "dns_flush_cache",
      description: "Flush the complete DNS cache. Requires confirm: true.",
      clientMethod: "flushCache",
      action: "flush_cache",
      actionLabel: "flush DNS cache"
    });

    server.registerTool(
      "dns_delete_cached",
      {
        description: "Delete a specific domain from the DNS cache.",
        inputSchema: dnsDeleteCachedSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_delete_cached",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.deleteCached({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_delete_cached",
            identity,
            requestId,
            action: "delete_cached_domain",
            applied: true,
            ok: true,
            target: {
              domain: args.domain
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
