import { emptyReadSchema, sessionDeleteSchema, sessionListSchema } from "../extraValidators.js";
import { appendAudit, getIncludeRaw, makeToolHandler, success, unwrapResponse } from "./shared.js";
import { confirmOrAudit, toMappedParams } from "./extraShared.js";

const sessionMap = {
  partial_token: "partialToken"
};

export const registerAdministrationTools = ({ server, context }) => {
  server.registerTool(
    "dns_whoami",
    {
      description: "Get the current Technitium API token session identity and permissions.",
      inputSchema: emptyReadSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_whoami",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getSession({ requestId });

        return success({
          response: unwrapResponse({ value: raw }),
          includeRaw: getIncludeRaw({ args, config: toolContext.config }),
          raw
        });
      }
    })
  );

  server.registerTool(
    "dns_metrics_prometheus",
    {
      description: "Get Technitium lifetime metrics in Prometheus text format.",
      inputSchema: emptyReadSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_metrics_prometheus",
      handler: async ({ context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getPrometheusMetrics({ requestId });

        return success({
          response: {
            text: raw.text ?? ""
          }
        });
      }
    })
  );

  server.registerTool(
    "dns_list_sessions",
    {
      description: "List active Technitium user and API-token sessions.",
      inputSchema: sessionListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_sessions",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listSessions({
          query: toMappedParams({ args }),
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
      "dns_delete_session",
      {
        description: "Delete a Technitium user or API-token session by partial token. Requires confirm: true.",
        inputSchema: sessionDeleteSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_delete_session",
        mutating: true,
        destructive: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const confirmError = confirmOrAudit({
            args,
            context: toolContext,
            toolName: "dns_delete_session",
            identity,
            requestId,
            action: "delete session"
          });
          if (confirmError) {
            return confirmError;
          }

          const raw = await toolContext.technitium.deleteSession({
            form: toMappedParams({ args, map: sessionMap }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_delete_session",
            identity,
            requestId,
            action: "delete_session",
            applied: true,
            ok: true,
            target: {
              partial_token: args.partial_token
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
