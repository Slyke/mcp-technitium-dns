import {
  dhcpLeaseDeleteSchema,
  dhcpLeaseListSchema,
  dhcpLeaseMutationSchema,
  dhcpRemoveReservedLeaseSchema,
  dhcpReservedLeaseSchema,
  dhcpScopeConfirmSchema,
  dhcpScopeNameSchema,
  dhcpScopeSetSchema
} from "../extraValidators.js";
import { appendAudit, getIncludeRaw, makeToolHandler, success, unwrapResponse } from "./shared.js";
import { assertAnyLeaseIdentity, confirmOrAudit, toMappedParams } from "./extraShared.js";

const dhcpMap = {
  hardware_address: "hardwareAddress",
  client_identifier: "clientIdentifier",
  host_name: "hostName",
  ip_address: "ipAddress",
  new_name: "newName",
  starting_address: "startingAddress",
  ending_address: "endingAddress",
  subnet_mask: "subnetMask",
  lease_time_days: "leaseTimeDays",
  lease_time_hours: "leaseTimeHours",
  lease_time_minutes: "leaseTimeMinutes",
  offer_delay_time: "offerDelayTime",
  ping_check_enabled: "pingCheckEnabled",
  ping_check_timeout: "pingCheckTimeout",
  ping_check_retries: "pingCheckRetries",
  domain_name: "domainName",
  domain_search_list: "domainSearchList",
  dns_updates: "dnsUpdates",
  dns_overwrite_for_dynamic_lease: "dnsOverwriteForDynamicLease",
  dns_ttl: "dnsTtl",
  server_address: "serverAddress",
  server_host_name: "serverHostName",
  boot_file_name: "bootFileName",
  router_address: "routerAddress",
  use_this_dns_server: "useThisDnsServer",
  dns_servers: "dnsServers",
  wins_servers: "winsServers",
  ntp_servers: "ntpServers",
  ntp_server_domain_names: "ntpServerDomainNames",
  static_routes: "staticRoutes",
  vendor_info: "vendorInfo",
  capwap_ac_ip_addresses: "capwapAcIpAddresses",
  tftp_server_addresses: "tftpServerAddresses",
  generic_options: "genericOptions",
  reserved_leases: "reservedLeases",
  allow_only_reserved_leases: "allowOnlyReservedLeases",
  block_locally_administered_mac_addresses: "blockLocallyAdministeredMacAddresses",
  ignore_client_identifier_option: "ignoreClientIdentifierOption"
};

const pipeRows = ({ rows, fields }) => {
  return rows
    .flatMap((row) => fields.map((field) => row[field] ?? ""))
    .join("|");
};

const scopeForm = ({ args }) => {
  const form = toMappedParams({
    args,
    map: dhcpMap,
    omit: ["static_routes", "vendor_info", "generic_options", "exclusions", "reserved_leases"]
  });

  if (args.static_routes) {
    form.staticRoutes = pipeRows({
      rows: args.static_routes,
      fields: ["destination", "subnet_mask", "router"]
    });
  }

  if (args.vendor_info) {
    form.vendorInfo = pipeRows({
      rows: args.vendor_info,
      fields: ["identifier", "information"]
    });
  }

  if (args.generic_options) {
    form.genericOptions = pipeRows({
      rows: args.generic_options,
      fields: ["code", "value"]
    });
  }

  if (args.exclusions) {
    form.exclusions = pipeRows({
      rows: args.exclusions,
      fields: ["starting_address", "ending_address"]
    });
  }

  if (args.reserved_leases) {
    form.reservedLeases = pipeRows({
      rows: args.reserved_leases,
      fields: ["host_name", "hardware_address", "address", "comments"]
    });
  }

  return form;
};

const registerReadTools = ({ server, context }) => {
  server.registerTool(
    "dns_dhcp_list_leases",
    {
      description: "List Technitium DHCP leases.",
      inputSchema: dhcpLeaseListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_list_leases",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listDhcpLeases({
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

  server.registerTool(
    "dns_dhcp_list_scopes",
    {
      description: "List Technitium DHCP scopes.",
      inputSchema: dhcpLeaseListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_list_scopes",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listDhcpScopes({
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

  server.registerTool(
    "dns_dhcp_get_scope",
    {
      description: "Get a full Technitium DHCP scope configuration.",
      inputSchema: dhcpScopeNameSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_get_scope",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.getDhcpScope({
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
};

const registerWriteTools = ({ server, context }) => {
  server.registerTool(
    "dns_dhcp_remove_lease",
    {
      description: "Remove a DHCP dynamic or reserved lease. Requires confirm: true.",
      inputSchema: dhcpLeaseDeleteSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_remove_lease",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const identityError = assertAnyLeaseIdentity({ args });
        if (identityError) {
          return identityError;
        }

        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_dhcp_remove_lease",
          identity,
          requestId,
          action: "remove DHCP lease"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.removeDhcpLease({
          form: toMappedParams({ args, map: dhcpMap }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_remove_lease",
          identity,
          requestId,
          action: "dhcp_remove_lease",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            hardware_address: args.hardware_address,
            client_identifier: args.client_identifier
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
    "dns_dhcp_convert_lease_reserved",
    {
      description: "Convert a DHCP dynamic lease to a reserved lease.",
      inputSchema: dhcpLeaseMutationSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_convert_lease_reserved",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const identityError = assertAnyLeaseIdentity({ args });
        if (identityError) {
          return identityError;
        }

        const raw = await toolContext.technitium.convertDhcpLeaseToReserved({
          form: toMappedParams({ args, map: dhcpMap }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_convert_lease_reserved",
          identity,
          requestId,
          action: "dhcp_convert_lease_reserved",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            hardware_address: args.hardware_address,
            client_identifier: args.client_identifier
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
    "dns_dhcp_convert_lease_dynamic",
    {
      description: "Convert a DHCP reserved lease to a dynamic lease.",
      inputSchema: dhcpLeaseMutationSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_convert_lease_dynamic",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const identityError = assertAnyLeaseIdentity({ args });
        if (identityError) {
          return identityError;
        }

        const raw = await toolContext.technitium.convertDhcpLeaseToDynamic({
          form: toMappedParams({ args, map: dhcpMap }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_convert_lease_dynamic",
          identity,
          requestId,
          action: "dhcp_convert_lease_dynamic",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            hardware_address: args.hardware_address,
            client_identifier: args.client_identifier
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
    "dns_dhcp_set_scope",
    {
      description: "Create or update a Technitium DHCP scope configuration.",
      inputSchema: dhcpScopeSetSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_set_scope",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.setDhcpScope({
          form: scopeForm({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_set_scope",
          identity,
          requestId,
          action: "dhcp_set_scope",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            new_name: args.new_name,
            keys: Object.keys(args)
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
    "dns_dhcp_add_reserved_lease",
    {
      description: "Add a reserved DHCP lease to a Technitium DHCP scope.",
      inputSchema: dhcpReservedLeaseSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_add_reserved_lease",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.addDhcpReservedLease({
          form: {
            ...toMappedParams({ args, map: dhcpMap, omit: ["address"] }),
            ipAddress: args.address
          },
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_add_reserved_lease",
          identity,
          requestId,
          action: "dhcp_add_reserved_lease",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            hardware_address: args.hardware_address,
            address: args.address,
            host_name: args.host_name
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
    "dns_dhcp_remove_reserved_lease",
    {
      description: "Remove a reserved DHCP lease from a Technitium DHCP scope. Requires confirm: true.",
      inputSchema: dhcpRemoveReservedLeaseSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_remove_reserved_lease",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_dhcp_remove_reserved_lease",
          identity,
          requestId,
          action: "remove DHCP reserved lease"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.removeDhcpReservedLease({
          form: toMappedParams({ args, map: dhcpMap }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_remove_reserved_lease",
          identity,
          requestId,
          action: "dhcp_remove_reserved_lease",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            hardware_address: args.hardware_address
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
    "dns_dhcp_enable_scope",
    {
      description: "Enable a Technitium DHCP scope.",
      inputSchema: dhcpScopeNameSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_enable_scope",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.enableDhcpScope({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_enable_scope",
          identity,
          requestId,
          action: "dhcp_enable_scope",
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

  server.registerTool(
    "dns_dhcp_disable_scope",
    {
      description: "Disable a Technitium DHCP scope while preserving its configuration.",
      inputSchema: dhcpScopeNameSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_disable_scope",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.disableDhcpScope({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_disable_scope",
          identity,
          requestId,
          action: "dhcp_disable_scope",
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

  server.registerTool(
    "dns_dhcp_delete_scope",
    {
      description: "Delete a Technitium DHCP scope permanently. Requires confirm: true.",
      inputSchema: dhcpScopeConfirmSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_dhcp_delete_scope",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_dhcp_delete_scope",
          identity,
          requestId,
          action: "delete DHCP scope"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.deleteDhcpScope({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_dhcp_delete_scope",
          identity,
          requestId,
          action: "dhcp_delete_scope",
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
};

export const registerDhcpTools = ({ server, context }) => {
  registerReadTools({ server, context });

  if (!context.config.readOnly) {
    registerWriteTools({ server, context });
  }
};
