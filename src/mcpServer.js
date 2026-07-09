import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAdministrationTools } from "./tools/administration.js";
import { registerAuditTools } from "./tools/auditTools.js";
import { registerBlockingCacheTools } from "./tools/blockingCache.js";
import { registerDhcpTools } from "./tools/dhcp.js";
import { registerDiagnosticTools } from "./tools/diagnostics.js";
import { registerDnssecExtraTools } from "./tools/dnssecExtras.js";
import { registerMaintenanceTools } from "./tools/maintenance.js";
import { registerSettingsAppsLogsDnssecTools } from "./tools/settingsAppsLogsDnssec.js";
import { registerZoneRecordTools } from "./tools/zonesRecords.js";

export const createMcpServer = ({ context, buildInfo }) => {
  const server = new McpServer(
    {
      name: "mcp-technitium-dns",
      version: buildInfo.version
    },
    {
      capabilities: {
        logging: {}
      }
    }
  );

  registerAuditTools({ server, context });
  registerDiagnosticTools({ server, context });
  registerAdministrationTools({ server, context });
  registerZoneRecordTools({ server, context });
  registerBlockingCacheTools({ server, context });
  registerSettingsAppsLogsDnssecTools({ server, context });
  registerDnssecExtraTools({ server, context });
  registerMaintenanceTools({ server, context });
  registerDhcpTools({ server, context });

  return server;
};
