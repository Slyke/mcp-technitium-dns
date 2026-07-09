import { dnssecConfirmZoneSchema, dnssecRolloverSchema, dnssecSignSchema } from "../extraValidators.js";
import { appendAudit, makeToolHandler, success, unwrapResponse } from "./shared.js";
import { confirmOrAudit, toMappedParams } from "./extraShared.js";

export const registerDnssecExtraTools = ({ server, context }) => {
  if (context.config.readOnly) {
    return;
  }

  server.registerTool(
    "dns_dnssec_sign",
    {
      description: "Sign a primary zone with DNSSEC using Technitium's DNSSEC signing API.",
      inputSchema: dnssecSignSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dnssec_sign",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.signZone({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dnssec_sign",
          identity,
          requestId,
          action: "dnssec_sign",
          applied: true,
          ok: true,
          target: {
            zone: args.zone,
            algorithm: args.algorithm
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
    "dns_dnssec_unsign",
    {
      description: "Remove DNSSEC signing from a primary zone. Requires confirm: true.",
      inputSchema: dnssecConfirmZoneSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dnssec_unsign",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_dnssec_unsign",
          identity,
          requestId,
          action: "unsign zone"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.unsignZone({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dnssec_unsign",
          identity,
          requestId,
          action: "dnssec_unsign",
          applied: true,
          ok: true,
          target: {
            zone: args.zone
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
    "dns_dnssec_rollover_key",
    {
      description: "Rollover a DNSSEC DNSKEY by key tag. Requires confirm: true.",
      inputSchema: dnssecRolloverSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dnssec_rollover_key",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_dnssec_rollover_key",
          identity,
          requestId,
          action: "rollover DNSSEC key"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.rolloverDnsKey({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dnssec_rollover_key",
          identity,
          requestId,
          action: "dnssec_rollover_key",
          applied: true,
          ok: true,
          target: {
            zone: args.zone,
            key_tag: args.key_tag
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
