# mcp-technitium-dns

Safety-focused MCP server for querying and managing Technitium DNS Server through the Technitium HTTP API. Codex or other MCP clients authenticate to this server with named Bearer tokens; this server authenticates to Technitium with a Technitium API token in the `Authorization: Bearer ...` header. Technitium credentials are never exposed to MCP clients.

Record tools use strict, validated snake_case inputs and map them to Technitium API parameters. For example, an A record uses `record: { ip_address: "192.0.2.10", ttl: 3600 }`; an MX record uses `record: { preference: 10, exchange: "mail.example.com" }`.

Zone export uses Technitium's required GET endpoint with a single-use API token created immediately before export.

`READ_ONLY=true` registers only read-only tools. Write tools require a readwrite MCP bearer token, and destructive tools require `confirm: true`.

## Technitium Setup

Target: Technitium DNS Server with API-token based automation.

- Use HTTPS for Technitium whenever possible.
- If Technitium is only available over HTTP, set `TECHNITIUM_ALLOW_HTTP_LOCAL=true`; the target host must still be local/private unless it is explicitly listed in `TECHNITIUM_ALLOW_HTTP_HOSTNAMES`.
- Create a dedicated Technitium user for MCP automation.
- Grant only the permissions needed for your intended tools.
- Store the Technitium API token in a protected file and use `TECHNITIUM_API_TOKEN_FILE` for production deployments.
- Set `READ_ONLY=true` when the server should expose only read-only MCP tools.

## Creating a Technitium API Token

1. Log in to the Technitium DNS web console as an administrator.
2. Create a dedicated user for MCP automation, or use an existing dedicated automation user.
3. Grant only the permissions needed for your intended tools. Read-only use needs view permissions for Dashboard, Zones, Cache, Allowed, Blocked, Apps, DNS Client, Settings, Administration, DHCP Server, and Logs. Write use needs modify/delete permissions for the sections you intend to manage.
4. Open the user menu/profile for that account and create an API token with a clear token name, for example `mcp-technitium-dns`.
5. Copy the generated token immediately.
6. Store it in a protected file and configure `TECHNITIUM_API_TOKEN_FILE`, or set `TECHNITIUM_API_TOKEN` for local testing.

The API token is passed to Technitium as `Authorization: Bearer <token>`. Do not configure your Technitium username/password in this MCP server.

## Safety Model

- HTTPS is the default for this MCP server.
- Technitium `TECHNITIUM_BASE_URL` must use HTTPS unless `TECHNITIUM_ALLOW_HTTP_LOCAL=true` and the target host is local/private.
- Write tools require a readwrite MCP bearer token.
- Destructive tools require `confirm: true`.
- All tool calls are rate-limited. Destructive tools have a stricter default limit.
- Audit entries are written to `data/audit.jsonl` by default.
- Set `AUDIT_MAX_ENTRIES` or `audit.maxEntries` to prune older records and keep only the newest entries.
- API responses and errors are sanitized to strip bearer tokens, passwords, stack traces, shared secrets, DNSSEC private keys, and sensitive local paths.

## Configuration

Required:

- `MCP_READ_BEARER_TOKENS` or `MCP_READWRITE_BEARER_TOKENS`
- `TECHNITIUM_BASE_URL`
- `TECHNITIUM_API_TOKEN` or `TECHNITIUM_API_TOKEN_FILE`

Bearer token variables are JSON5 arrays:

```json5
[{ name: "reader1", token: "replace-me" }]
```

Token files are also supported:

```json5
[{ name: "reader1", tokenFile: "./data/mcp-reader.token" }]
```

Copy `.env.example` to `.env` for environment-based local development, or copy `config.example.json5` to `data/config.json5` for file-based configuration. Environment variables override `data/config.json5`. `BACKUP_DIR` stores ZIP files created by `dns_backup_settings`; `IMPORT_DIR` is where ZIP files must be placed before `dns_restore_settings` or `dns_update_app` can read them.

Set `AUDIT_RECORD_READS=true` or `audit.recordReads: true` to append read-only MCP calls to the audit file for troubleshooting. Audit entries store request metadata, identity name, tool name, redacted arguments, result count when available, and error code when a tool returns an error; they do not store unsanitized Technitium response bodies.

If HTTPS is enabled and `server.crt`/`server.key` are missing in `CERTS_DIR`, the server generates a local self-signed certificate.

<details>
<summary>Common optional variables</summary>

```env
CONFIG_FILE=./data/config.json5
HTTPS_ENABLED=true
HTTPS_HOST=0.0.0.0
HTTPS_PORT=3443
HTTP_ENABLED=false
HTTP_HOST=0.0.0.0
HTTP_PORT=3000
READ_ONLY=false
TECHNITIUM_TIMEOUT_MS=10000
TECHNITIUM_TLS_REJECT_UNAUTHORIZED=true
TECHNITIUM_ALLOW_HTTP_LOCAL=false
TECHNITIUM_ALLOW_HTTP_HOSTNAMES=
READY_CHECK_TECHNITIUM=false
AUTH_HEALTHCHECKS=false
AUDIT_ENABLED=true
AUDIT_FILE=./data/audit.jsonl
AUDIT_RECORD_READS=false
AUDIT_MAX_ENTRIES=0
BACKUP_DIR=./data/backups
IMPORT_DIR=./data/imports
CERTS_DIR=./data/certs
INCLUDE_RAW_DEFAULT=false
RATE_LIMIT_READ_MAX=120
RATE_LIMIT_READ_WINDOW_MS=60000
RATE_LIMIT_WRITE_MAX=30
RATE_LIMIT_WRITE_WINDOW_MS=60000
RATE_LIMIT_DESTRUCTIVE_MAX=5
RATE_LIMIT_DESTRUCTIVE_WINDOW_MS=60000
```

</details>

## Docker

Build and run a local image:

```bash
mkdir -p data
printf '%s\n' 'replace-technitium-api-token' > data/technitium-api.token
docker build -t mcp-technitium-dns:local .
docker run --rm \
  -p 3443:3443 \
  -v "$PWD/data:/app/data" \
  -e MCP_READ_BEARER_TOKENS='[{name:"reader1",token:"read-token"}]' \
  -e MCP_READWRITE_BEARER_TOKENS='[{name:"admin1",token:"write-token"}]' \
  -e TECHNITIUM_BASE_URL='https://technitium.lan:53443' \
  -e TECHNITIUM_API_TOKEN_FILE='./data/technitium-api.token' \
  mcp-technitium-dns:local
```

## Kubernetes

<details>
<summary>Kubernetes manifest</summary>

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: technitium-dns-mcp
type: Opaque
stringData:
  MCP_READ_BEARER_TOKENS: '[{name:"reader1",token:"read-token"}]'
  MCP_READWRITE_BEARER_TOKENS: '[{name:"admin1",token:"write-token"}]'
  TECHNITIUM_BASE_URL: 'https://technitium.lan:53443'
  TECHNITIUM_API_TOKEN: 'replace-me'
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: technitium-dns-mcp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: technitium-dns-mcp
  template:
    metadata:
      labels:
        app: technitium-dns-mcp
    spec:
      containers:
        - name: server
          image: slyke/mcp-technitium-dns:latest
          ports:
            - containerPort: 3443
          envFrom:
            - secretRef:
                name: technitium-dns-mcp
          env:
            - name: HTTPS_ENABLED
              value: "true"
            - name: HTTP_ENABLED
              value: "false"
            - name: READY_CHECK_TECHNITIUM
              value: "false"
          readinessProbe:
            httpGet:
              path: /readyz
              port: 3443
              scheme: HTTPS
          livenessProbe:
            httpGet:
              path: /healthz
              port: 3443
              scheme: HTTPS
```

</details>

## Codex MCP Config

<details>
<summary>Full Codex MCP config</summary>

```toml
[mcp_servers.technitium_dns]
url = "https://technitium-dns-mcp.lan:3443/mcp"
bearer_token_env_var = "TECHNITIUM_DNS_MCP_TOKEN"
default_tools_approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_health_check]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_get_stats]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_list_zones]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_list_records]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_zone_options]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_resolve]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_get_settings]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_query_logs]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_audit_search]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_whoami]
approval_mode = "auto"

[mcp_servers.technitium_dns.tools.dns_create_zone]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_delete_zone]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_add_record]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_update_record]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_delete_record]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_set_settings]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_flush_cache]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_backup_settings]
approval_mode = "prompt"

[mcp_servers.technitium_dns.tools.dns_restore_settings]
approval_mode = "prompt"
```

</details>

## Tools

Read-only tools:

- `dns_health_check`
- `dns_get_stats`
- `dns_check_update`
- `dns_resolve`
- `dns_list_zones`
- `dns_zone_options`
- `dns_export_zone`
- `dns_list_records`
- `dns_list_blocked`
- `dns_list_allowed`
- `dns_list_cache`
- `dns_get_settings`
- `dns_query_logs`
- `dns_list_apps`
- `dns_list_app_store`
- `dns_get_app_config`
- `dns_dnssec_info`
- `dns_get_ds`
- `dns_audit_list`
- `dns_audit_search`
- `dns_audit_read`
- `dns_whoami`
- `dns_metrics_prometheus`
- `dns_list_sessions`
- `dns_list_tsig_keys`
- `dns_list_log_files`
- `dns_read_log_file`
- `dns_export_query_logs`
- `dns_dhcp_list_leases`
- `dns_dhcp_list_scopes`
- `dns_dhcp_get_scope`

Write tools:

- `dns_create_zone`
- `dns_delete_zone`
- `dns_enable_zone`
- `dns_disable_zone`
- `dns_set_zone_options`
- `dns_add_record`
- `dns_update_record`
- `dns_delete_record`
- `dns_block_domain`
- `dns_remove_blocked`
- `dns_flush_blocked`
- `dns_allow_domain`
- `dns_remove_allowed`
- `dns_flush_allowed`
- `dns_flush_cache`
- `dns_delete_cached`
- `dns_set_settings`
- `dns_update_blocklists`
- `dns_temp_disable_blocking`
- `dns_install_app`
- `dns_uninstall_app`
- `dns_delete_session`
- `dns_dnssec_sign`
- `dns_dnssec_unsign`
- `dns_dnssec_rollover_key`
- `dns_backup_settings`
- `dns_restore_settings`
- `dns_download_update_app`
- `dns_update_app`
- `dns_set_app_config`
- `dns_delete_log_file`
- `dns_delete_all_logs`
- `dns_dhcp_remove_lease`
- `dns_dhcp_convert_lease_reserved`
- `dns_dhcp_convert_lease_dynamic`
- `dns_dhcp_set_scope`
- `dns_dhcp_add_reserved_lease`
- `dns_dhcp_remove_reserved_lease`
- `dns_dhcp_enable_scope`
- `dns_dhcp_disable_scope`
- `dns_dhcp_delete_scope`

`READ_ONLY=true` omits all write tools at registration time. Destructive write tools require `confirm: true`; these include deleting zones/records/sessions/logs/DHCP scopes, flushing cache/allow/block lists, uninstalling apps, restoring settings, unsigning or rolling DNSSEC keys, and removing DHCP leases.

## CLI MCP Clients

This server exposes Streamable HTTP MCP at `/mcp`. Start the server first, then point CLI clients at `https://<host>:3443/mcp` and use one of the configured MCP bearer tokens.

### Claude Code

For a one-machine setup, add the remote HTTP server with an Authorization header:

```bash
export TECHNITIUM_DNS_MCP_TOKEN="replace-read-or-readwrite-token"
claude mcp add --transport http technitium-dns https://technitium-dns-mcp.lan:3443/mcp \
  --header "Authorization: Bearer ${TECHNITIUM_DNS_MCP_TOKEN}"
claude
```

For a project-shareable config, create `.mcp.json` and keep the token in the environment:

```json
{
  "mcpServers": {
    "technitium-dns": {
      "type": "http",
      "url": "https://technitium-dns-mcp.lan:3443/mcp",
      "headers": {
        "Authorization": "Bearer ${TECHNITIUM_DNS_MCP_TOKEN}"
      }
    }
  }
}
```

Run `TECHNITIUM_DNS_MCP_TOKEN="replace-read-or-readwrite-token" claude`, then use `/mcp` inside Claude Code to confirm the server is connected.

### Codex CLI

Codex CLI uses `config.toml` for Streamable HTTP MCP servers. Add this to `~/.codex/config.toml`, or to `.codex/config.toml` in a trusted project:

```toml
[mcp_servers.technitium_dns]
url = "https://technitium-dns-mcp.lan:3443/mcp"
bearer_token_env_var = "TECHNITIUM_DNS_MCP_TOKEN"
default_tools_approval_mode = "prompt"
```

Then run:

```bash
export TECHNITIUM_DNS_MCP_TOKEN="replace-read-or-readwrite-token"
codex
```

Use `/mcp` in the Codex TUI to confirm the server is connected. `codex mcp add` is useful for stdio MCP servers; for this HTTP server, use the TOML form above.

## Development

```bash
npm install
npm test
mkdir -p data/certs data/backups data/imports
cp config.example.json5 data/config.json5
node src/index.js
```

Health endpoints return:

```json
{
  "ok": true,
  "version": "0.1.0",
  "buildHash": "unknown",
  "readOnly": false
}
```

## Image Publishing

See [IMAGE_PUBLISHING.md](./IMAGE_PUBLISHING.md) for the versioned image tagging and publishing workflow.

## License

Released under the MIT License. See [LICENSE.md](./LICENSE.md).
