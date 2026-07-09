import { auditListSchema, auditReadSchema } from "../extraValidators.js";
import { makeToolHandler, success } from "./shared.js";

const searchAudit = ({ audit, args }) => {
  const limit = args.limit ?? 100;
  const offset = args.offset ?? 0;
  return audit.search({
    ...args,
    limit,
    offset
  });
};

export const registerAuditTools = ({ server, context }) => {
  server.registerTool(
    "dns_audit_list",
    {
      description: "List recent local MCP audit.jsonl entries in reverse chronological order.",
      inputSchema: auditListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_audit_list",
      handler: async ({ args, context: toolContext }) => {
        const entries = searchAudit({
          audit: toolContext.audit,
          args
        });

        return success({
          response: {
            entries,
            count: entries.length,
            limit: args.limit ?? 100,
            offset: args.offset ?? 0
          }
        });
      }
    })
  );

  server.registerTool(
    "dns_audit_search",
    {
      description: "Search local MCP audit.jsonl entries by text, tool, identity, action, request id, result, and date range.",
      inputSchema: auditListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_audit_search",
      handler: async ({ args, context: toolContext }) => {
        const entries = searchAudit({
          audit: toolContext.audit,
          args
        });

        return success({
          response: {
            entries,
            count: entries.length,
            limit: args.limit ?? 100,
            offset: args.offset ?? 0
          }
        });
      }
    })
  );

  server.registerTool(
    "dns_audit_read",
    {
      description: "Read one local MCP audit.jsonl entry by request_id.",
      inputSchema: auditReadSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_audit_read",
      handler: async ({ args, context: toolContext }) => {
        return success({
          response: {
            entry: toolContext.audit.get({
              request_id: args.request_id
            })
          }
        });
      }
    })
  );
};
