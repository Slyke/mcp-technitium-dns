import { randomUUID } from "node:crypto";
import { hasWriteScope } from "../auth.js";
import {
  authError,
  confirmationError,
  rateLimitError,
  readOnlyError,
  technitiumError,
  timeoutError,
  toMcpResult,
  unknownError
} from "../errors.js";
import { TechnitiumClientError } from "../technitiumClient.js";

export const createRequestId = () => {
  return randomUUID();
};

export const getIdentity = ({ extra }) => {
  return {
    name: extra?.authInfo?.clientId ?? "unknown",
    role: extra?.authInfo?.scopes?.includes("write") ? "readwrite" : "read",
    scopes: extra?.authInfo?.scopes ?? []
  };
};

export const getIncludeRaw = ({ args, config }) => {
  return args.include_raw ?? config.includeRawDefault;
};

export const cleanObject = ({ value }) => {
  return Object.fromEntries(
    Object.entries(value ?? {}).filter(([, nested]) => nested !== undefined && nested !== null && nested !== "")
  );
};

export const unwrapResponse = ({ value }) => {
  if (value?.response !== undefined) {
    return value.response;
  }

  return value;
};

const apiParamNames = {
  filter_name: "filterName",
  filter_type: "filterType",
  page_number: "pageNumber",
  zones_per_page: "zonesPerPage",
  include_available_catalog_zone_names: "includeAvailableCatalogZoneNames",
  include_available_tsig_key_names: "includeAvailableTsigKeyNames",
  list_zone: "listZone",
  dont_trim_query_type_data: "dontTrimQueryTypeData",
  e_dns_client_subnet: "eDnsClientSubnet",
  use_soa_serial_date_scheme: "useSoaSerialDateScheme",
  primary_name_server_addresses: "primaryNameServerAddresses",
  zone_transfer_protocol: "zoneTransferProtocol",
  tsig_key_name: "tsigKeyName",
  validate_zone: "validateZone",
  initialize_forwarder: "initializeForwarder",
  override_catalog_query_access: "overrideCatalogQueryAccess",
  override_catalog_zone_transfer: "overrideCatalogZoneTransfer",
  override_catalog_notify: "overrideCatalogNotify",
  primary_zone_transfer_protocol: "primaryZoneTransferProtocol",
  primary_zone_transfer_tsig_key_name: "primaryZoneTransferTsigKeyName",
  query_access: "queryAccess",
  query_access_network_acl: "queryAccessNetworkACL",
  zone_transfer: "zoneTransfer",
  zone_transfer_network_acl: "zoneTransferNetworkACL",
  zone_transfer_tsig_key_names: "zoneTransferTsigKeyNames",
  notify_name_servers: "notifyNameServers",
  notify_secondary_catalogs_name_servers: "notifySecondaryCatalogsNameServers",
  update_network_acl: "updateNetworkACL",
  update_security_policies: "updateSecurityPolicies",
  client_ip_address: "clientIpAddress",
  response_type: "responseType",
  class_path: "classPath",
  entries_per_page: "entriesPerPage",
  descending_order: "descendingOrder",
  ip_address: "ipAddress",
  update_svcb_hints: "updateSvcbHints",
  name_server: "nameServer",
  ptr_name: "ptrName",
  primary_name_server: "primaryNameServer",
  responsible_person: "responsiblePerson",
  split_text: "splitText",
  character_strings_base64: "characterStringsBase64",
  txt_domain: "txtDomain",
  naptr_order: "naptrOrder",
  naptr_preference: "naptrPreference",
  naptr_flags: "naptrFlags",
  naptr_services: "naptrServices",
  naptr_regexp: "naptrRegexp",
  naptr_replacement: "naptrReplacement",
  key_tag: "keyTag",
  digest_type: "digestType",
  sshfp_algorithm: "sshfpAlgorithm",
  sshfp_fingerprint_type: "sshfpFingerprintType",
  sshfp_fingerprint: "sshfpFingerprint",
  tlsa_certificate_usage: "tlsaCertificateUsage",
  tlsa_selector: "tlsaSelector",
  tlsa_matching_type: "tlsaMatchingType",
  tlsa_certificate_association_data: "tlsaCertificateAssociationData",
  svc_priority: "svcPriority",
  svc_target_name: "svcTargetName",
  svc_params: "svcParams",
  uri_priority: "uriPriority",
  uri_weight: "uriWeight",
  forwarder_priority: "forwarderPriority",
  dnssec_validation: "dnssecValidation",
  proxy_type: "proxyType",
  proxy_address: "proxyAddress",
  proxy_port: "proxyPort",
  proxy_username: "proxyUsername",
  proxy_password: "proxyPassword",
  app_name: "appName",
  record_data: "recordData"
};

const newParamName = ({ key }) => {
  const apiName = apiParamNames[key] ?? key;
  return `new${apiName.charAt(0).toUpperCase()}${apiName.slice(1)}`;
};

export const toApiParams = ({ args, prefixNew = false }) => {
  return cleanObject({
    value: Object.fromEntries(
      Object.entries(args ?? {}).map(([key, value]) => [
        prefixNew ? newParamName({ key }) : (apiParamNames[key] ?? key),
        Array.isArray(value) ? value.join(",") : value
      ])
    )
  });
};

export const requireConfirm = ({ args, action }) => {
  if (args.confirm !== true) {
    return confirmationError({
      message: `${action} requires confirm: true.`
    });
  }

  return null;
};

const appendAuditSafe = ({ context, entry }) => {
  try {
    context.audit.append(entry);
  } catch (err) {
    context.logger.generateLog({
      level: "warn",
      caller: "tools::audit",
      loggerKey: "MCP_AUDIT_APPEND_FAILED",
      message: "Failed to append audit entry.",
      correlationId: entry.requestId,
      error: err
    });
  }
};

const errorPayloadFromThrown = ({ err, toolName }) => {
  if (err instanceof TechnitiumClientError) {
    if (err.code === "timeout") {
      return timeoutError({
        message: err.message,
        details: err.details
      });
    }

    return technitiumError({
      message: err.message,
      details: err.details
    });
  }

  return unknownError({
    message: "Tool execution failed.",
    details: {
      tool_name: toolName
    }
  });
};

export const makeToolHandler = ({ context, toolName, mutating = false, destructive = false, handler }) => {
  return async (args, extra) => {
    const requestId = createRequestId();
    const identity = getIdentity({ extra });
    const rateCategory = destructive ? "destructive" : (mutating ? "write" : "read");

    context.logger.generateLog({
      level: "info",
      caller: `tools::${toolName}`,
      loggerKey: "MCP_TOOL_CALL",
      message: "MCP tool called.",
      correlationId: requestId,
      context: {
        request_id: requestId,
        tool_name: toolName,
        identity_name: identity.name,
        role: identity.role,
        mutating,
        destructive
      }
    });

    const rate = context.rateLimiter.check({
      identityName: identity.name,
      toolName,
      category: rateCategory
    });

    if (!rate.ok) {
      context.logger.generateLog({
        level: "warn",
        caller: `tools::${toolName}`,
        loggerKey: "RATE_LIMIT_BLOCKED",
        message: "MCP tool call rate limited.",
        correlationId: requestId,
        context: {
          tool_name: toolName,
          identity_name: identity.name,
          category: rateCategory,
          retry_after_seconds: rate.retryAfterSeconds
        }
      });

      const payload = rateLimitError({
        details: {
          retry_after_seconds: rate.retryAfterSeconds,
          limit: rate.limit,
          window_ms: rate.windowMs
        }
      });
      return toMcpResult({ payload });
    }

    try {
      if (mutating && context.config.readOnly) {
        const payload = readOnlyError();
        appendAuditSafe({
          context,
          entry: {
            toolName,
            identityName: identity.name,
            action: "blocked_read_only",
            applied: false,
            ok: false,
            requestId,
            target: args
          }
        });
        return toMcpResult({ payload });
      }

      if (mutating && !hasWriteScope({ identity })) {
        const payload = authError({
          message: "Bearer token is not allowed to call mutating tools."
        });
        appendAuditSafe({
          context,
          entry: {
            toolName,
            identityName: identity.name,
            action: "blocked_auth",
            applied: false,
            ok: false,
            requestId,
            target: args
          }
        });
        return toMcpResult({ payload });
      }

      const payload = await handler({
        args,
        extra,
        context,
        identity,
        requestId
      });

      if (!mutating && context.config.audit.recordReads) {
        appendAuditSafe({
          context,
          entry: {
            toolName,
            identityName: identity.name,
            action: "read",
            applied: false,
            ok: payload?.ok !== false,
            requestId,
            target: {
              args,
              result_ok: payload?.ok !== false
            }
          }
        });
      }

      return toMcpResult({ payload });
    } catch (err) {
      context.logger.generateError({
        caller: `tools::${toolName}`,
        reason: "Tool execution failed.",
        errorKey: "MCP_TOOL_FAILED",
        err,
        includeStackTrace: false,
        correlationId: requestId,
        context: {
          request_id: requestId,
          tool_name: toolName,
          identity_name: identity.name
        }
      });

      const payload = errorPayloadFromThrown({
        err,
        toolName
      });

      if (mutating) {
        appendAuditSafe({
          context,
          entry: {
            toolName,
            identityName: identity.name,
            action: "failed",
            applied: false,
            ok: false,
            requestId,
            target: {
              args,
              error_code: payload.error?.code
            }
          }
        });
      }

      return toMcpResult({ payload });
    }
  };
};

export const appendAudit = ({ context, toolName, identity, requestId, action, applied, ok, target }) => {
  return appendAuditSafe({
    context,
    entry: {
      toolName,
      identityName: identity.name,
      action,
      applied,
      ok,
      requestId,
      target
    }
  });
};

export const success = ({ response, includeRaw = false, raw }) => {
  return {
    ok: true,
    response,
    ...(includeRaw
      ? {
        raw
      }
      : {})
  };
};
