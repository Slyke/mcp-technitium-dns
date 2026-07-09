import {
  dnsAddRecordSchema,
  dnsCreateZoneSchema,
  dnsDeleteRecordSchema,
  dnsDeleteZoneSchema,
  dnsExportZoneSchema,
  dnsListRecordsSchema,
  dnsListZonesSchema,
  dnsSetZoneOptionsSchema,
  dnsUpdateRecordSchema,
  dnsZoneOptionsSchema,
  zoneSchema
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

const baseZoneForm = ({ args }) => {
  return toApiParams({
    args: {
      zone: args.zone,
      node: args.node
    }
  });
};

const recordBaseForm = ({ args }) => {
  return toApiParams({
    args: {
      domain: args.domain,
      zone: args.zone,
      type: args.type,
      node: args.node
    }
  });
};

const confirmOrReturn = ({ args, action, context, toolName, identity, requestId }) => {
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

export const registerZoneRecordTools = ({ server, context }) => {
  server.registerTool(
    "dns_list_zones",
    {
      description: "List authoritative DNS zones configured in Technitium DNS Server.",
      inputSchema: dnsListZonesSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_zones",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listZones({
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
    "dns_zone_options",
    {
      description: "Get zone DNSSEC, transfer, notify, dynamic update, and ACL options.",
      inputSchema: dnsZoneOptionsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_zone_options",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getZoneOptions({
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
    "dns_export_zone",
    {
      description: "Export an authoritative zone file in BIND format using Technitium's required GET endpoint with a single-use token.",
      inputSchema: dnsExportZoneSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_export_zone",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.exportZone({
          query: toApiParams({ args }),
          requestId
        });

        return {
          ok: true,
          zone: args.zone,
          zone_file: raw.text ?? ""
        };
      }
    })
  );

  server.registerTool(
    "dns_list_records",
    {
      description: "List records for a domain or entire authoritative zone.",
      inputSchema: dnsListRecordsSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_records",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getRecords({
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
      "dns_create_zone",
      {
        description: "Create a new authoritative DNS zone.",
        inputSchema: dnsCreateZoneSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_create_zone",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.createZone({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_create_zone",
            identity,
            requestId,
            action: "create_zone",
            applied: true,
            ok: true,
            target: {
              zone: args.zone,
              type: args.type
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
      "dns_delete_zone",
      {
        description: "Delete an authoritative DNS zone. Requires confirm: true.",
        inputSchema: dnsDeleteZoneSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_delete_zone",
        mutating: true,
        destructive: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const confirmError = confirmOrReturn({
            args,
            action: "delete zone",
            context: toolContext,
            toolName: "dns_delete_zone",
            identity,
            requestId
          });
          if (confirmError) {
            return confirmError;
          }

          const raw = await toolContext.technitium.deleteZone({
            form: baseZoneForm({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_delete_zone",
            identity,
            requestId,
            action: "delete_zone",
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
      "dns_enable_zone",
      {
        description: "Enable a disabled authoritative zone.",
        inputSchema: zoneSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_enable_zone",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.enableZone({
            form: baseZoneForm({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_enable_zone",
            identity,
            requestId,
            action: "enable_zone",
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
      "dns_disable_zone",
      {
        description: "Disable an authoritative zone while preserving records.",
        inputSchema: zoneSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_disable_zone",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.disableZone({
            form: baseZoneForm({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_disable_zone",
            identity,
            requestId,
            action: "disable_zone",
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
      "dns_set_zone_options",
      {
        description: "Update zone notify, transfer ACL, query ACL, catalog, and dynamic update options.",
        inputSchema: dnsSetZoneOptionsSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_set_zone_options",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.setZoneOptions({
            form: toApiParams({ args }),
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_set_zone_options",
            identity,
            requestId,
            action: "set_zone_options",
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
      "dns_add_record",
      {
        description: "Add a DNS record to an authoritative zone.",
        inputSchema: dnsAddRecordSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_add_record",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.addRecord({
            form: {
              ...recordBaseForm({ args }),
              ...toApiParams({ args: args.record })
            },
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_add_record",
            identity,
            requestId,
            action: "add_record",
            applied: true,
            ok: true,
            target: {
              zone: args.zone,
              domain: args.domain,
              type: args.type
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
      "dns_update_record",
      {
        description: "Update an existing DNS record by matching its current record fields and providing replacement fields.",
        inputSchema: dnsUpdateRecordSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_update_record",
        mutating: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const raw = await toolContext.technitium.updateRecord({
            form: {
              ...recordBaseForm({ args }),
              ...toApiParams({ args: args.match }),
              ...toApiParams({ args: args.updates, prefixNew: true })
            },
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_update_record",
            identity,
            requestId,
            action: "update_record",
            applied: true,
            ok: true,
            target: {
              zone: args.zone,
              domain: args.domain,
              type: args.type
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
      "dns_delete_record",
      {
        description: "Delete a DNS record from an authoritative zone. Requires confirm: true.",
        inputSchema: dnsDeleteRecordSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true
        }
      },
      makeToolHandler({
        context,
        toolName: "dns_delete_record",
        mutating: true,
        destructive: true,
        handler: async ({ args, context: toolContext, identity, requestId }) => {
          const confirmError = confirmOrReturn({
            args,
            action: "delete record",
            context: toolContext,
            toolName: "dns_delete_record",
            identity,
            requestId
          });
          if (confirmError) {
            return confirmError;
          }

          const raw = await toolContext.technitium.deleteRecord({
            form: {
              ...recordBaseForm({ args }),
              ...toApiParams({ args: args.record })
            },
            requestId
          });

          appendAudit({
            context: toolContext,
            toolName: "dns_delete_record",
            identity,
            requestId,
            action: "delete_record",
            applied: true,
            ok: true,
            target: {
              zone: args.zone,
              domain: args.domain,
              type: args.type
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
