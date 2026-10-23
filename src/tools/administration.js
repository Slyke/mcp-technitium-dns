import { apiTokenCreateFileSchema, emptyReadSchema, sessionDeleteSchema, sessionListSchema } from "../extraValidators.js";
import { reserveSecretFile } from "../secretFile.js";
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
      "dns_create_api_token_file",
      {
        description: "Create a non-expiring Technitium API token for an existing user and write its one-time value directly to a bounded mode-0600 server-side file. The token value is never returned. Requires confirm: true.",
        inputSchema: apiTokenCreateFileSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_create_api_token_file",
        mutating: true,
        destructive: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const confirmError = confirmOrAudit({
            args,
            context: toolContext,
            toolName: "dns_create_api_token_file",
            identity,
            requestId,
            action: "create non-expiring API token"
          });
          if (confirmError) {
            return confirmError;
          }

          const existingRaw = await toolContext.technitium.listSessions({ requestId });
          const existingResponse = unwrapResponse({ value: existingRaw });
          const existingSessions = Array.isArray(existingResponse?.sessions) ? existingResponse.sessions : [];
          const duplicate = existingSessions.find((session) => {
            return session?.type === "ApiToken"
              && session?.username === args.user
              && session?.tokenName === args.token_name;
          });

          if (duplicate) {
            return {
              ok: false,
              error: {
                code: "resource_exists",
                message: "An API token session with this user and token_name already exists."
              }
            };
          }

          const reservation = reserveSecretFile({
            directory: toolContext.config.storage.secretOutputDir,
            fileName: args.file_name
          });

          let token;
          try {
            token = await toolContext.technitium.createAdminApiToken({
              form: {
                user: args.user,
                tokenName: args.token_name
              },
              requestId
            });
          } catch (err) {
            reservation.abort();
            throw err;
          }

          try {
            reservation.commit({ value: token });
          } catch (writeError) {
            reservation.abort();
            try {
              const rollbackRaw = await toolContext.technitium.listSessions({ requestId });
              const rollbackResponse = unwrapResponse({ value: rollbackRaw });
              const rollbackSessions = Array.isArray(rollbackResponse?.sessions) ? rollbackResponse.sessions : [];
              const created = rollbackSessions.find((session) => {
                return session?.type === "ApiToken"
                  && session?.username === args.user
                  && session?.tokenName === args.token_name
                  && session?.partialToken;
              });
              if (!created) {
                throw new Error("Created token session was not found for rollback.");
              }
              await toolContext.technitium.deleteSession({
                form: { partialToken: created.partialToken },
                requestId
              });
            } catch {
              return {
                ok: false,
                error: {
                  code: "outcome_unknown",
                  message: "API token creation succeeded but secret-file publication failed and rollback could not be confirmed; inspect Technitium sessions before retrying."
                }
              };
            }
            return {
              ok: false,
              error: {
                code: "publication_failed",
                message: "The token file could not be published and token revocation was attempted. Verify Technitium sessions before retrying."
              }
            };
          }

          appendAudit({
            context: toolContext,
            toolName: "dns_create_api_token_file",
            identity,
            requestId,
            action: "create_api_token_file",
            applied: true,
            ok: true,
            target: {
              user: args.user,
              token_name: args.token_name,
              file_name: args.file_name
            }
          });

          return success({
            response: {
              username: args.user,
              tokenName: args.token_name,
              fileName: args.file_name,
              written: true
            }
          });
        }
      })
    );

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
