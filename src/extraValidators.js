import { z } from "zod";
import { isCidr, isIpAddress, isRfc1035Domain, nodeField, RECORD_TYPES } from "./validators.js";

const includeRawField = {
  include_raw: z.boolean().optional()
};

const optionalBoolean = z.boolean().optional();
const optionalString = z.string().trim().optional();
const dateStringSchema = z.string().trim().refine((value) => Number.isFinite(Date.parse(value)), {
  message: "Must be a parseable date/time string."
});
const domainSchema = z.string().trim().refine((value) => isRfc1035Domain({ value }), {
  message: "Must be a valid RFC 1035 domain name."
});
const ipSchema = z.string().trim().refine((value) => isIpAddress({ value }), {
  message: "Must be a valid IPv4 or IPv6 address."
});
const cidrSchema = z.string().trim().refine((value) => isCidr({ value }), {
  message: "Must be a valid IPv4 or IPv6 CIDR."
});
const safeNameSchema = z.string().trim().min(1).max(255).refine((value) => {
  return value !== "." && value !== ".." && !/[\\/]/.test(value) && !value.includes("\0");
}, {
  message: "Must be a file/name value, not a path."
});
const appNameSchema = z.string().trim().min(1).max(128);
const classPathSchema = z.string().trim().min(1).max(512);
const macSchema = z.string().trim().regex(/^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/, "Must be a MAC address.");
const hexSchema = z.string().trim().regex(/^(?:[0-9A-Fa-f]{2}:?)+$/, "Must be hexadecimal bytes.").optional();
const identifierSchema = z.string().trim().min(1).max(255);
const pipeSafeSchema = z.string().trim().max(1024).refine((value) => !value.includes("|"), {
  message: "Must not include pipe separators."
});

const leaseIdentityFields = {
  name: z.string().trim().min(1).max(128),
  hardware_address: macSchema.optional(),
  client_identifier: identifierSchema.optional(),
  ...nodeField
};

const logFilterFields = {
  name: appNameSchema,
  class_path: classPathSchema,
  start: optionalString,
  end: optionalString,
  client_ip_address: ipSchema.optional(),
  protocol: z.enum(["Udp", "Tcp", "Tls", "Https", "Quic"]).optional(),
  response_type: z.enum(["Authoritative", "Recursive", "Cached", "Blocked", "UpstreamBlocked", "CacheBlocked"]).optional(),
  rcode: optionalString,
  qname: domainSchema.optional(),
  qtype: z.enum(RECORD_TYPES).optional(),
  qclass: z.enum(["IN", "CH", "HS", "ANY"]).optional(),
  ...nodeField
};

export const auditListSchema = {
  limit: z.number().int().min(1).max(1000).default(100).optional(),
  offset: z.number().int().min(0).max(1000000).default(0).optional(),
  query: z.string().trim().min(1).max(512).optional(),
  tool_name: z.string().trim().min(1).max(128).optional(),
  identity_name: z.string().trim().min(1).max(128).optional(),
  action: z.string().trim().min(1).max(128).optional(),
  request_id: z.string().trim().min(1).max(128).optional(),
  applied: z.boolean().optional(),
  ok: z.boolean().optional(),
  from: dateStringSchema.optional(),
  to: dateStringSchema.optional()
};

export const auditReadSchema = {
  request_id: z.string().trim().min(1).max(128)
};

export const emptyReadSchema = {
  ...includeRawField
};

export const nodeReadSchema = {
  ...nodeField,
  ...includeRawField
};

export const dnssecSignSchema = {
  zone: domainSchema,
  algorithm: z.enum(["RSA", "ECDSA", "EDDSA"]),
  pem_ksk_private_key: z.string().min(1).max(12000).optional(),
  pem_zsk_private_key: z.string().min(1).max(12000).optional(),
  hash_algorithm: z.enum(["MD5", "SHA1", "SHA256", "SHA512"]).optional(),
  ksk_key_size: z.number().int().min(1024).max(8192).optional(),
  zsk_key_size: z.number().int().min(1024).max(8192).optional(),
  curve: z.enum(["P256", "P384", "ED25519", "ED448"]).optional(),
  dns_key_ttl: z.number().int().min(0).max(2147483647).optional(),
  zsk_rollover_days: z.number().int().min(0).max(3650).optional(),
  nx_proof: z.enum(["NSEC", "NSEC3"]).optional(),
  iterations: z.number().int().min(0).max(2500).optional(),
  salt_length: z.number().int().min(0).max(255).optional(),
  ...nodeField
};

export const dnssecConfirmZoneSchema = {
  zone: domainSchema,
  confirm: z.boolean(),
  ...nodeField
};

export const dnssecRolloverSchema = {
  zone: domainSchema,
  key_tag: z.number().int().min(0).max(65535),
  confirm: z.boolean(),
  ...nodeField
};

export const backupSettingsSchema = {
  file_name: safeNameSchema.optional(),
  block_lists: optionalBoolean,
  logs: optionalBoolean,
  stats: optionalBoolean,
  scopes: optionalBoolean,
  apps: optionalBoolean,
  zones: optionalBoolean,
  allowed: optionalBoolean,
  blocked: optionalBoolean,
  dns_settings: optionalBoolean,
  log_settings: optionalBoolean,
  web_service_settings: optionalBoolean,
  auth_config: optionalBoolean,
  cluster_config: optionalBoolean,
  ...nodeField
};

export const restoreSettingsSchema = {
  file_name: safeNameSchema,
  source_dir: z.enum(["backup", "import"]).default("backup").optional(),
  block_lists: optionalBoolean,
  logs: optionalBoolean,
  stats: optionalBoolean,
  scopes: optionalBoolean,
  apps: optionalBoolean,
  zones: optionalBoolean,
  allowed: optionalBoolean,
  blocked: optionalBoolean,
  dns_settings: optionalBoolean,
  log_settings: optionalBoolean,
  web_service_settings: optionalBoolean,
  auth_config: optionalBoolean,
  cluster_config: optionalBoolean,
  delete_existing_files: optionalBoolean,
  confirm: z.boolean(),
  ...nodeField
};

export const appDownloadUpdateSchema = {
  name: appNameSchema,
  url: z.string().url().refine((value) => value.startsWith("https://"), {
    message: "App update URL must use HTTPS."
  }),
  ...nodeField
};

export const appManualUpdateSchema = {
  name: appNameSchema,
  package_file: safeNameSchema,
  ...nodeField
};

export const appSetConfigSchema = {
  name: appNameSchema,
  config: z.record(z.string().trim().min(1).max(128), z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
  ])),
  ...nodeField
};

export const dhcpLeaseListSchema = {
  ...nodeField,
  ...includeRawField
};

export const dhcpLeaseMutationSchema = leaseIdentityFields;

export const dhcpLeaseDeleteSchema = {
  ...leaseIdentityFields,
  confirm: z.boolean()
};

export const dhcpReservedLeaseSchema = {
  name: z.string().trim().min(1).max(128),
  hardware_address: macSchema,
  address: ipSchema,
  host_name: domainSchema.optional(),
  comments: z.string().trim().max(512).optional(),
  ...nodeField
};

export const dhcpRemoveReservedLeaseSchema = {
  name: z.string().trim().min(1).max(128),
  hardware_address: macSchema,
  confirm: z.boolean(),
  ...nodeField
};

export const dhcpScopeNameSchema = {
  name: z.string().trim().min(1).max(128),
  ...nodeField,
  ...includeRawField
};

export const dhcpScopeConfirmSchema = {
  name: z.string().trim().min(1).max(128),
  confirm: z.boolean(),
  ...nodeField
};

const staticRouteSchema = z.object({
  destination: ipSchema,
  subnet_mask: ipSchema,
  router: ipSchema
}).strict();

const vendorInfoSchema = z.object({
  identifier: pipeSafeSchema,
  information: z.string().trim().min(1).max(4096)
}).strict();

const genericOptionSchema = z.object({
  code: z.number().int().min(1).max(254),
  value: z.string().trim().min(1).max(4096)
}).strict();

const exclusionSchema = z.object({
  starting_address: ipSchema,
  ending_address: ipSchema
}).strict();

const reservedLeaseSchema = z.object({
  host_name: domainSchema.optional(),
  hardware_address: macSchema,
  address: ipSchema,
  comments: pipeSafeSchema.optional()
}).strict();

export const dhcpScopeSetSchema = {
  name: z.string().trim().min(1).max(128),
  new_name: z.string().trim().min(1).max(128).optional(),
  starting_address: ipSchema.optional(),
  ending_address: ipSchema.optional(),
  subnet_mask: ipSchema.optional(),
  lease_time_days: z.number().int().min(0).max(3650).optional(),
  lease_time_hours: z.number().int().min(0).max(23).optional(),
  lease_time_minutes: z.number().int().min(0).max(59).optional(),
  offer_delay_time: z.number().int().min(0).max(600000).optional(),
  ping_check_enabled: optionalBoolean,
  ping_check_timeout: z.number().int().min(0).max(600000).optional(),
  ping_check_retries: z.number().int().min(0).max(100).optional(),
  domain_name: domainSchema.optional(),
  domain_search_list: z.array(domainSchema).max(64).optional(),
  dns_updates: optionalBoolean,
  dns_overwrite_for_dynamic_lease: optionalBoolean,
  dns_ttl: z.number().int().min(0).max(2147483647).optional(),
  server_address: ipSchema.optional(),
  server_host_name: domainSchema.optional(),
  boot_file_name: z.string().trim().max(255).optional(),
  router_address: ipSchema.optional(),
  use_this_dns_server: optionalBoolean,
  dns_servers: z.array(ipSchema).max(64).optional(),
  wins_servers: z.array(ipSchema).max(64).optional(),
  ntp_servers: z.array(ipSchema).max(64).optional(),
  ntp_server_domain_names: z.array(domainSchema).max(64).optional(),
  static_routes: z.array(staticRouteSchema).max(256).optional(),
  vendor_info: z.array(vendorInfoSchema).max(256).optional(),
  capwap_ac_ip_addresses: z.array(ipSchema).max(64).optional(),
  tftp_server_addresses: z.array(ipSchema).max(64).optional(),
  generic_options: z.array(genericOptionSchema).max(256).optional(),
  exclusions: z.array(exclusionSchema).max(256).optional(),
  reserved_leases: z.array(reservedLeaseSchema).max(4096).optional(),
  allow_only_reserved_leases: optionalBoolean,
  block_locally_administered_mac_addresses: optionalBoolean,
  ignore_client_identifier_option: optionalBoolean,
  ...nodeField
};

export const sessionListSchema = {
  ...nodeField,
  ...includeRawField
};

export const sessionDeleteSchema = {
  partial_token: z.string().trim().min(4).max(128),
  confirm: z.boolean(),
  ...nodeField
};

export const logFileListSchema = {
  ...nodeField,
  ...includeRawField
};

export const logFileReadSchema = {
  file_name: safeNameSchema,
  limit_mb: z.number().int().min(0).max(1024).default(0).optional(),
  ...nodeField
};

export const logFileDeleteSchema = {
  file_name: safeNameSchema,
  confirm: z.boolean(),
  ...nodeField
};

export const logDeleteAllSchema = {
  confirm: z.boolean(),
  ...nodeField
};

export const logExportSchema = {
  ...logFilterFields
};
