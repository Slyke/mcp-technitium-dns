import fs from "node:fs";
import {
  appDownloadUpdateSchema,
  appManualUpdateSchema,
  appSetConfigSchema,
  backupSettingsSchema,
  logDeleteAllSchema,
  logExportSchema,
  logFileDeleteSchema,
  logFileListSchema,
  logFileReadSchema,
  nodeReadSchema,
  restoreSettingsSchema
} from "../extraValidators.js";
import { appendAudit, getIncludeRaw, makeToolHandler, success, unwrapResponse } from "./shared.js";
import { backupFileName, confirmOrAudit, ensureChildFile, toMappedParams, writeBufferFile } from "./extraShared.js";

const backupMap = {
  block_lists: "blockLists",
  allowed: "allowedZones",
  blocked: "blockedZones",
  dns_settings: "dnsSettings",
  log_settings: "logSettings",
  web_service_settings: "webServiceSettings",
  auth_config: "authConfig",
  cluster_config: "clusterConfig",
  delete_existing_files: "deleteExistingFiles"
};

const logMap = {
  class_path: "classPath",
  page_number: "pageNumber",
  entries_per_page: "entriesPerPage",
  descending_order: "descendingOrder",
  client_ip_address: "clientIpAddress",
  response_type: "responseType",
  file_name: "fileName",
  limit_mb: "limit"
};

const selectedBackupFlags = ({ args }) => {
  return Object.fromEntries(
    Object.entries(args)
      .filter(([key, value]) => Object.prototype.hasOwnProperty.call(backupMap, key) && typeof value === "boolean")
  );
};

const registerReadTools = ({ server, context }) => {
  server.registerTool(
    "dns_list_tsig_keys",
    {
      description: "List configured TSIG key names without exposing shared secrets.",
      inputSchema: nodeReadSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_tsig_keys",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listTsigKeyNames({
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
    "dns_list_log_files",
    {
      description: "List Technitium DNS server log files.",
      inputSchema: logFileListSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_list_log_files",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.listLogFiles({
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
    "dns_read_log_file",
    {
      description: "Read a Technitium DNS server log file, optionally limited by megabytes.",
      inputSchema: logFileReadSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_read_log_file",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.downloadLogFile({
          query: toMappedParams({ args, map: logMap }),
          requestId
        });

        return success({
          response: {
            file_name: args.file_name,
            text: raw.text ?? ""
          }
        });
      }
    })
  );

  server.registerTool(
    "dns_export_query_logs",
    {
      description: "Export filtered Technitium DNS app query logs as CSV text.",
      inputSchema: logExportSchema,
      annotations: {
        readOnlyHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_export_query_logs",
      handler: async ({ args, context: toolContext, requestId }) => {
        const raw = await toolContext.technitium.exportQueryLogs({
          query: toMappedParams({ args, map: logMap }),
          requestId
        });

        return success({
          response: {
            csv: raw.text ?? ""
          }
        });
      }
    })
  );
};

const registerWriteTools = ({ server, context }) => {
  server.registerTool(
    "dns_backup_settings",
    {
      description: "Create a Technitium settings backup ZIP in the configured local backup directory. Requires write scope because backups can contain secrets.",
      inputSchema: backupSettingsSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_backup_settings",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.backupSettings({
          query: toMappedParams({ args, map: backupMap, omit: ["file_name"] }),
          requestId
        });
        const fileName = args.file_name ?? backupFileName({ requestId });
        writeBufferFile({
          directory: toolContext.config.storage.backupDir,
          fileName,
          buffer: raw.buffer
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_backup_settings",
          identity,
          requestId,
          action: "backup_settings",
          applied: true,
          ok: true,
          target: {
            file_name: fileName,
            selected: selectedBackupFlags({ args })
          }
        });

        return success({
          response: {
            file_name: fileName,
            bytes: raw.buffer.length,
            content_type: raw.contentType
          }
        });
      }
    })
  );

  server.registerTool(
    "dns_restore_settings",
    {
      description: "Restore Technitium settings from a ZIP in the configured backup/import directory. Requires confirm: true.",
      inputSchema: restoreSettingsSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_restore_settings",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_restore_settings",
          identity,
          requestId,
          action: "restore settings"
        });
        if (confirmError) {
          return confirmError;
        }

        const rootDir = (args.source_dir ?? "backup") === "import"
          ? toolContext.config.storage.importDir
          : toolContext.config.storage.backupDir;
        const filePath = ensureChildFile({
          rootDir,
          fileName: args.file_name
        });

        if (!fs.existsSync(filePath)) {
          throw new Error("Configured restore package file was not found.");
        }

        const raw = await toolContext.technitium.restoreSettings({
          query: toMappedParams({ args, map: backupMap, omit: ["file_name", "source_dir"] }),
          filePath,
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_restore_settings",
          identity,
          requestId,
          action: "restore_settings",
          applied: true,
          ok: true,
          target: {
            file_name: args.file_name,
            source_dir: args.source_dir ?? "backup",
            selected: selectedBackupFlags({ args }),
            delete_existing_files: args.delete_existing_files === true
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
    "dns_download_update_app",
    {
      description: "Download and update an installed Technitium DNS app from an HTTPS ZIP URL.",
      inputSchema: appDownloadUpdateSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_download_update_app",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const raw = await toolContext.technitium.downloadUpdateApp({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_download_update_app",
          identity,
          requestId,
          action: "download_update_app",
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
    "dns_update_app",
    {
      description: "Manually update an installed Technitium DNS app from a ZIP in the configured local import directory.",
      inputSchema: appManualUpdateSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_update_app",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const filePath = ensureChildFile({
          rootDir: toolContext.config.storage.importDir,
          fileName: args.package_file
        });

        if (!fs.existsSync(filePath)) {
          throw new Error("Configured app package file was not found.");
        }

        const raw = await toolContext.technitium.updateApp({
          form: toMappedParams({ args, omit: ["package_file"] }),
          filePath,
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_update_app",
          identity,
          requestId,
          action: "update_app",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            package_file: args.package_file
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
    "dns_set_app_config",
    {
      description: "Set an installed Technitium DNS app config object.",
      inputSchema: appSetConfigSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_set_app_config",
      mutating: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const form = toMappedParams({ args, omit: ["config"] });
        form.config = JSON.stringify(args.config);
        const raw = await toolContext.technitium.setAppConfig({
          form,
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_set_app_config",
          identity,
          requestId,
          action: "set_app_config",
          applied: true,
          ok: true,
          target: {
            name: args.name,
            keys: Object.keys(args.config)
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
    "dns_delete_log_file",
    {
      description: "Delete a Technitium DNS server log file. Requires confirm: true.",
      inputSchema: logFileDeleteSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_delete_log_file",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_delete_log_file",
          identity,
          requestId,
          action: "delete log file"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.deleteLogFile({
          form: {
            log: args.file_name,
            ...toMappedParams({ args, omit: ["file_name"] })
          },
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_delete_log_file",
          identity,
          requestId,
          action: "delete_log_file",
          applied: true,
          ok: true,
          target: {
            file_name: args.file_name
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
    "dns_delete_all_logs",
    {
      description: "Delete all Technitium DNS server log files. Requires confirm: true.",
      inputSchema: logDeleteAllSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true
      }
    },
    makeToolHandler({
      context,
      toolName: "dns_delete_all_logs",
      mutating: true,
      destructive: true,
      handler: async ({ args, context: toolContext, identity, requestId }) => {
        const confirmError = confirmOrAudit({
          args,
          context: toolContext,
          toolName: "dns_delete_all_logs",
          identity,
          requestId,
          action: "delete all logs"
        });
        if (confirmError) {
          return confirmError;
        }

        const raw = await toolContext.technitium.deleteAllLogs({
          form: toMappedParams({ args }),
          requestId
        });

        appendAudit({
          context: toolContext,
          toolName: "dns_delete_all_logs",
          identity,
          requestId,
          action: "delete_all_logs",
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
};

export const registerMaintenanceTools = ({ server, context }) => {
  registerReadTools({ server, context });

  if (!context.config.readOnly) {
    registerWriteTools({ server, context });
  }
};
