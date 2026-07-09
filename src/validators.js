import net from "node:net";
import { z } from "zod";

const optionalString = z.string().trim().optional();
const optionalBoolean = z.boolean().optional();
const includeRawField = {
  include_raw: optionalBoolean
};

export const RECORD_TYPES = [
  "A",
  "AAAA",
  "NS",
  "CNAME",
  "SOA",
  "PTR",
  "MX",
  "TXT",
  "RP",
  "SRV",
  "NAPTR",
  "DS",
  "SSHFP",
  "TLSA",
  "SVCB",
  "HTTPS",
  "URI",
  "CAA",
  "ANAME",
  "DNAME",
  "FWD",
  "APP",
  "ANY",
  "UNKNOWN"
];

const ZONE_TYPES = ["Primary", "Secondary", "Stub", "Forwarder", "SecondaryForwarder", "Catalog", "SecondaryCatalog"];
const PROTOCOLS = ["Udp", "Tcp", "Tls", "Https", "Quic"];
const STATS_DURATIONS = ["LastHour", "LastDay", "LastWeek", "LastMonth", "LastYear", "Custom", "custom"];
const RESPONSE_TYPES = ["Authoritative", "Recursive", "Cached", "Blocked", "UpstreamBlocked", "CacheBlocked"];
const ZONE_ACCESS = ["Deny", "Allow", "AllowOnlyPrivateNetworks", "AllowOnlyZoneNameServers", "UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL"];
const ZONE_TRANSFER = ["Deny", "Allow", "AllowOnlyZoneNameServers", "UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL"];
const NOTIFY_MODES = ["None", "ZoneNameServers", "SpecifiedNameServers", "BothZoneAndSpecifiedNameServers", "SeparateNameServersForCatalogAndMemberZones"];
const UPDATE_MODES = ["Deny", "Allow", "AllowOnlyZoneNameServers", "UseSpecifiedNetworkACL", "AllowZoneNameServersAndUseSpecifiedNetworkACL"];
const DIGEST_TYPES = ["SHA1", "SHA256", "GOST-R-34-11-94", "SHA384"];
const SSHFP_ALGORITHMS = ["RSA", "DSA", "ECDSA", "Ed25519", "Ed448"];
const TLSA_CERTIFICATE_USAGES = ["PKIX_TA", "PKIX_EE", "DANE_TA", "DANE_EE"];
const TLSA_SELECTORS = ["Cert", "SPKI"];
const MATCHING_TYPES = ["Full", "SHA256", "SHA512"];
const CAA_TAGS = ["issue", "issuewild", "iodef", "contactemail", "contactphone", "accounturi", "validationmethods"];
const PROXY_TYPES = ["NoProxy", "DefaultProxy", "Http", "Socks5"];

const SETTINGS_KEYS = [
  "dnsServerDomain",
  "dnsServerLocalEndPoints",
  "dnsServerIPv4SourceAddresses",
  "dnsServerIPv6SourceAddresses",
  "defaultRecordTtl",
  "defaultNsRecordTtl",
  "defaultSoaRecordTtl",
  "defaultResponsiblePerson",
  "useSoaSerialDateScheme",
  "minSoaRefresh",
  "minSoaRetry",
  "zoneTransferAllowedNetworks",
  "notifyAllowedNetworks",
  "dnsServerEnableCheckForUpdate",
  "dnsAppsEnableAutomaticUpdate",
  "ipv6Mode",
  "preferIPv6",
  "enableUdpSocketPool",
  "socketPoolExcludedPorts",
  "udpPayloadSize",
  "dnssecValidation",
  "eDnsClientSubnet",
  "eDnsClientSubnetIPv4PrefixLength",
  "eDnsClientSubnetIPv6PrefixLength",
  "eDnsClientSubnetIpv4Override",
  "eDnsClientSubnetIpv6Override",
  "qpmPrefixLimitsIPv4",
  "qpmPrefixLimitsIPv6",
  "qpmLimitSampleMinutes",
  "qpmLimitUdpTruncationPercentage",
  "qpmLimitBypassList",
  "clientTimeout",
  "tcpSendTimeout",
  "tcpReceiveTimeout",
  "quicIdleTimeout",
  "quicMaxInboundStreams",
  "listenBacklog",
  "udpSendBufferSizeKB",
  "udpReceiveBufferSizeKB",
  "maxConcurrentResolutionsPerCore",
  "webServiceLocalAddresses",
  "webServiceHttpPort",
  "webServiceEnableHttpUnixSocket",
  "webServiceHttpUnixSocket",
  "webServiceEnableTls",
  "webServiceEnableHttp3",
  "webServiceHttpToTlsRedirect",
  "webServiceUseSelfSignedTlsCertificate",
  "webServiceTlsPort",
  "webServiceReverseProxyAddresses",
  "webServiceRealIpHeader",
  "webServiceCspFrameAncestorsHeader",
  "webServiceTlsCertificatePath",
  "webServiceTlsCertificatePassword",
  "enableEDnsClientSubnetSourceAddress",
  "enableDnsOverUdpProxy",
  "enableDnsOverTcpProxy",
  "enableDnsOverHttp",
  "enableDnsOverHttpUnixSocket",
  "enableDnsOverTls",
  "enableDnsOverHttps",
  "enableDnsOverHttp3",
  "enableDnsOverQuic",
  "enableDnsOverHttpHelpRedirect",
  "dnsOverUdpProxyPort",
  "dnsOverTcpProxyPort",
  "dnsOverHttpPort",
  "dnsOverHttpUnixSocket",
  "dnsOverTlsPort",
  "dnsOverHttpsPort",
  "dnsOverQuicPort",
  "dnsReverseProxyNetworkACL",
  "dnsOverHttpRealIpHeader",
  "dnsTlsCertificatePath",
  "dnsTlsCertificatePassword",
  "recursion",
  "recursionNetworkACL",
  "randomizeName",
  "qnameMinimization",
  "locallyServedDnsZones",
  "resolverRetries",
  "resolverTimeout",
  "resolverConcurrency",
  "resolverMaxStackCount",
  "saveCache",
  "serveStale",
  "serveStaleTtl",
  "serveStaleAnswerTtl",
  "serveStaleResetTtl",
  "serveStaleMaxWaitTime",
  "cacheMaximumEntries",
  "cacheMinimumRecordTtl",
  "cacheMaximumRecordTtl",
  "cacheNegativeRecordTtl",
  "cacheFailureRecordTtl",
  "cachePrefetchEligibility",
  "cachePrefetchTrigger",
  "cachePrefetchSampleIntervalInMinutes",
  "cachePrefetchSampleEligibilityHitsPerHour",
  "enableBlocking",
  "allowTxtBlockingReport",
  "blockingBypassList",
  "blockingType",
  "blockingAnswerTtl",
  "customBlockingAddresses",
  "blockListUrls",
  "blockListUpdateIntervalHours",
  "proxy",
  "forwarders",
  "forwarderProtocol",
  "concurrentForwarding",
  "forwarderRetries",
  "forwarderTimeout",
  "forwarderConcurrency",
  "enableLogging",
  "loggingType",
  "ignoreResolverLogs",
  "logQueries",
  "noStackTrace",
  "useLocalTime",
  "logFolder",
  "maxLogFileDays",
  "enableInMemoryStats",
  "maxStatFileDays"
];

const normalizeDomain = ({ value }) => {
  return String(value ?? "").trim().replace(/\.$/, "").toLowerCase();
};

export const isRfc1035Domain = ({ value, allowWildcard = false, allowRoot = false }) => {
  const normalized = normalizeDomain({ value });

  if (allowRoot && normalized === "") {
    return true;
  }

  if (!normalized || normalized.length > 253) {
    return false;
  }

  const labels = normalized.split(".");
  return labels.every((label, index) => {
    if (allowWildcard && index === 0 && label === "*") {
      return true;
    }

    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  });
};

export const isIpAddress = ({ value }) => {
  return net.isIP(String(value ?? "").trim()) !== 0;
};

export const isCidr = ({ value }) => {
  const [address, prefixText] = String(value ?? "").trim().split("/");
  const version = net.isIP(address);
  const prefix = Number(prefixText);

  if (!version || !Number.isInteger(prefix)) {
    return false;
  }

  return version === 4 ? prefix >= 0 && prefix <= 32 : prefix >= 0 && prefix <= 128;
};

const isDomainIpOrCidr = ({ value }) => {
  return isRfc1035Domain({ value }) || isIpAddress({ value }) || isCidr({ value });
};

const isAclValue = ({ value }) => {
  const raw = String(value ?? "").trim();
  if (raw === "false") {
    return true;
  }

  const items = raw.split(",").map((item) => item.trim()).filter(Boolean);
  return items.every((item) => {
    const stripped = item.startsWith("!") ? item.slice(1) : item;
    return isIpAddress({ value: stripped }) || isCidr({ value: stripped });
  });
};

const domainSchema = z.string().trim().refine((value) => isRfc1035Domain({ value }), {
  message: "Must be a valid RFC 1035 domain name."
});
const browsableDomainSchema = z.string().trim().refine((value) => isRfc1035Domain({ value, allowRoot: true }), {
  message: "Must be empty or a valid RFC 1035 domain name."
});
const wildcardDomainSchema = z.string().trim().refine((value) => isRfc1035Domain({ value, allowWildcard: true }), {
  message: "Must be a valid RFC 1035 domain name, optionally with a leading wildcard."
});
const ipSchema = z.string().trim().refine((value) => isIpAddress({ value }), {
  message: "Must be a valid IPv4 or IPv6 address."
});
const cidrSchema = z.string().trim().refine((value) => isCidr({ value }), {
  message: "Must be a valid IPv4 or IPv6 CIDR."
});
const domainIpOrCidrSchema = z.string().trim().refine((value) => isDomainIpOrCidr({ value }), {
  message: "Must be a valid RFC 1035 domain, IP address, or CIDR."
});
const aclSchema = z.string().trim().refine((value) => isAclValue({ value }), {
  message: "Must be false or a comma-separated ACL of IP/CIDR entries with optional ! denies."
});

const stringListSchema = z.union([z.array(z.string().trim().min(1)), z.string().trim().min(1)]).optional();
const int32Schema = z.number().int().min(0).max(2147483647).optional();
const portSchema = z.number().int().min(1).max(65535).optional();
const hexSchema = z.string().trim().regex(/^(?:[0-9A-Fa-f]{2}:?)+$/, "Must be hexadecimal bytes.").optional();

export const nodeField = {
  node: z.union([domainSchema, z.literal("cluster")]).optional()
};

const recordPayloadSchema = z.object({
  ttl: int32Schema,
  disabled: optionalBoolean,
  ip_address: ipSchema.optional(),
  update_svcb_hints: optionalBoolean,
  name_server: domainSchema.optional(),
  ptr_name: domainSchema.optional(),
  cname: domainSchema.optional(),
  primary_name_server: domainSchema.optional(),
  responsible_person: domainSchema.optional(),
  serial: int32Schema,
  refresh: int32Schema,
  retry: int32Schema,
  expire: int32Schema,
  minimum: int32Schema,
  preference: z.number().int().min(0).max(65535).optional(),
  exchange: domainSchema.optional(),
  text: z.string().optional(),
  split_text: optionalBoolean,
  character_strings_base64: stringListSchema,
  mailbox: domainSchema.optional(),
  txt_domain: domainSchema.optional(),
  priority: z.number().int().min(0).max(65535).optional(),
  weight: z.number().int().min(0).max(65535).optional(),
  port: portSchema,
  target: domainSchema.optional(),
  naptr_order: z.number().int().min(0).max(65535).optional(),
  naptr_preference: z.number().int().min(0).max(65535).optional(),
  naptr_flags: z.string().trim().max(32).optional(),
  naptr_services: z.string().trim().max(256).optional(),
  naptr_regexp: z.string().max(1024).optional(),
  naptr_replacement: domainSchema.optional(),
  dname: domainSchema.optional(),
  key_tag: z.number().int().min(0).max(65535).optional(),
  algorithm: z.string().trim().min(1).max(64).optional(),
  digest_type: z.enum(DIGEST_TYPES).optional(),
  digest: hexSchema,
  sshfp_algorithm: z.enum(SSHFP_ALGORITHMS).optional(),
  sshfp_fingerprint_type: z.enum(["SHA1", "SHA256"]).optional(),
  sshfp_fingerprint: hexSchema,
  tlsa_certificate_usage: z.enum(TLSA_CERTIFICATE_USAGES).optional(),
  tlsa_selector: z.enum(TLSA_SELECTORS).optional(),
  tlsa_matching_type: z.enum(MATCHING_TYPES).optional(),
  tlsa_certificate_association_data: hexSchema,
  svc_priority: z.number().int().min(0).max(65535).optional(),
  svc_target_name: domainSchema.optional(),
  svc_params: z.union([z.string().trim(), z.literal(false)]).optional(),
  uri_priority: z.number().int().min(0).max(65535).optional(),
  uri_weight: z.number().int().min(0).max(65535).optional(),
  uri: z.string().url().optional(),
  flags: z.number().int().min(0).max(255).optional(),
  tag: z.enum(CAA_TAGS).optional(),
  value: z.string().trim().min(1).optional(),
  aname: domainSchema.optional(),
  protocol: z.enum(PROTOCOLS).optional(),
  forwarder: z.string().trim().min(1).optional(),
  forwarder_priority: z.number().int().min(0).max(65535).optional(),
  dnssec_validation: optionalBoolean,
  proxy_type: z.enum(PROXY_TYPES).optional(),
  proxy_address: z.string().trim().min(1).optional(),
  proxy_port: portSchema,
  proxy_username: z.string().trim().max(256).optional(),
  proxy_password: z.string().max(1024).optional(),
  app_name: z.string().trim().min(1).max(128).optional(),
  class_path: z.string().trim().min(1).max(512).optional(),
  record_data: z.string().max(8192).optional(),
  rdata: hexSchema
}).strict();

const settingsValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(z.union([z.string(), z.number(), z.boolean()]))
]);

const settingsPatchSchema = z.record(z.string(), settingsValueSchema).refine((value) => {
  return Object.keys(value).every((key) => SETTINGS_KEYS.includes(key));
}, {
  message: "settings contains unsupported Technitium setting keys."
});

export const dnsHealthCheckSchema = {
  domain: domainSchema.optional(),
  type: z.enum(RECORD_TYPES).default("A").optional(),
  ...nodeField,
  ...includeRawField
};

export const dnsGetStatsSchema = {
  type: z.enum(STATS_DURATIONS).default("LastHour").optional(),
  utc: optionalBoolean,
  dont_trim_query_type_data: optionalBoolean,
  start: optionalString,
  end: optionalString,
  ...nodeField,
  ...includeRawField
};

export const dnsCheckUpdateSchema = {
  ...includeRawField
};

export const dnsResolveSchema = {
  server: z.string().trim().min(1).default("this-server").optional(),
  domain: domainSchema,
  type: z.enum(RECORD_TYPES).default("A").optional(),
  protocol: z.enum(PROTOCOLS).default("Udp").optional(),
  dnssec: optionalBoolean,
  e_dns_client_subnet: z.union([ipSchema, cidrSchema]).optional(),
  ...nodeField,
  ...includeRawField
};

export const dnsListZonesSchema = {
  filter_name: optionalString,
  filter_type: z.enum(ZONE_TYPES).optional(),
  page_number: z.number().int().min(1).optional(),
  zones_per_page: z.number().int().min(1).max(1000).optional(),
  ...nodeField,
  ...includeRawField
};

export const zoneSchema = {
  zone: domainIpOrCidrSchema,
  ...nodeField
};

export const dnsZoneOptionsSchema = {
  zone: domainSchema,
  include_available_catalog_zone_names: optionalBoolean,
  include_available_tsig_key_names: optionalBoolean,
  ...nodeField,
  ...includeRawField
};

export const dnsExportZoneSchema = {
  zone: domainSchema,
  ...nodeField
};

export const dnsListRecordsSchema = {
  domain: wildcardDomainSchema,
  zone: domainSchema.optional(),
  list_zone: optionalBoolean,
  ...nodeField,
  ...includeRawField
};

export const hierarchicalListSchema = {
  domain: browsableDomainSchema.default("").optional(),
  direction: z.enum(["up", "down"]).default("down").optional(),
  ...nodeField,
  ...includeRawField
};

export const dnsGetSettingsSchema = {
  ...includeRawField
};

export const dnsQueryLogsSchema = {
  name: z.string().trim().min(1),
  class_path: z.string().trim().min(1),
  page_number: z.number().int().min(1).default(1).optional(),
  entries_per_page: z.number().int().min(1).max(1000).default(100).optional(),
  descending_order: z.boolean().default(true).optional(),
  start: optionalString,
  end: optionalString,
  client_ip_address: ipSchema.optional(),
  protocol: z.enum(PROTOCOLS).optional(),
  response_type: z.enum(RESPONSE_TYPES).optional(),
  rcode: optionalString,
  qname: domainSchema.optional(),
  qtype: z.enum(RECORD_TYPES).optional(),
  qclass: z.enum(["IN", "CH", "HS", "ANY"]).optional(),
  ...nodeField,
  ...includeRawField
};

export const dnsListAppsSchema = {
  ...nodeField,
  ...includeRawField
};

export const dnsGetAppConfigSchema = {
  name: z.string().trim().min(1),
  ...nodeField,
  ...includeRawField
};

export const dnsDnssecInfoSchema = {
  zone: domainSchema,
  ...nodeField,
  ...includeRawField
};

export const dnsCreateZoneSchema = {
  zone: domainIpOrCidrSchema,
  type: z.enum(ZONE_TYPES).default("Primary").optional(),
  catalog: domainSchema.optional(),
  use_soa_serial_date_scheme: optionalBoolean,
  primary_name_server_addresses: stringListSchema,
  zone_transfer_protocol: z.enum(["Tcp", "Tls", "Quic"]).optional(),
  tsig_key_name: domainSchema.optional(),
  validate_zone: optionalBoolean,
  initialize_forwarder: optionalBoolean,
  protocol: z.enum(PROTOCOLS).optional(),
  forwarder: z.string().trim().min(1).optional(),
  ...nodeField
};

export const dnsDeleteZoneSchema = {
  zone: domainSchema,
  confirm: z.boolean(),
  ...nodeField
};

export const dnsSetZoneOptionsSchema = {
  zone: domainSchema,
  disabled: optionalBoolean,
  catalog: domainSchema.optional(),
  override_catalog_query_access: optionalBoolean,
  override_catalog_zone_transfer: optionalBoolean,
  override_catalog_notify: optionalBoolean,
  primary_name_server_addresses: stringListSchema,
  primary_zone_transfer_protocol: z.enum(["Tcp", "Tls", "Quic"]).optional(),
  primary_zone_transfer_tsig_key_name: domainSchema.optional(),
  validate_zone: optionalBoolean,
  query_access: z.enum(ZONE_ACCESS).optional(),
  query_access_network_acl: aclSchema.optional(),
  zone_transfer: z.enum(ZONE_TRANSFER).optional(),
  zone_transfer_network_acl: aclSchema.optional(),
  zone_transfer_tsig_key_names: z.union([stringListSchema.unwrap(), z.literal(false)]).optional(),
  notify: z.enum(NOTIFY_MODES).optional(),
  notify_name_servers: stringListSchema,
  notify_secondary_catalogs_name_servers: stringListSchema,
  update: z.enum(UPDATE_MODES).optional(),
  update_network_acl: aclSchema.optional(),
  update_security_policies: z.union([z.string().trim().min(1), z.literal(false)]).optional(),
  ...nodeField
};

export const dnsAddRecordSchema = {
  domain: wildcardDomainSchema,
  zone: domainSchema.optional(),
  type: z.enum(RECORD_TYPES),
  record: recordPayloadSchema.default({}).optional(),
  ...nodeField
};

export const dnsUpdateRecordSchema = {
  domain: wildcardDomainSchema,
  zone: domainSchema.optional(),
  type: z.enum(RECORD_TYPES),
  match: recordPayloadSchema.default({}).optional(),
  updates: recordPayloadSchema,
  ...nodeField
};

export const dnsDeleteRecordSchema = {
  domain: wildcardDomainSchema,
  zone: domainSchema.optional(),
  type: z.enum(RECORD_TYPES),
  record: recordPayloadSchema.default({}).optional(),
  confirm: z.boolean(),
  ...nodeField
};

export const domainMutationSchema = {
  domain: domainSchema,
  ...nodeField
};

export const flushConfirmSchema = {
  confirm: z.boolean(),
  ...nodeField
};

export const dnsDeleteCachedSchema = {
  domain: domainSchema,
  ...nodeField
};

export const dnsSetSettingsSchema = {
  settings: settingsPatchSchema,
  merge_existing: z.boolean().default(false).optional()
};

export const dnsTempDisableBlockingSchema = {
  minutes: z.number().int().min(1).max(1440),
  ...nodeField
};

export const dnsInstallAppSchema = {
  name: z.string().trim().min(1),
  url: z.string().url().refine((value) => value.startsWith("https://"), {
    message: "App install URL must use HTTPS."
  })
};

export const dnsUninstallAppSchema = {
  name: z.string().trim().min(1),
  confirm: z.boolean(),
  ...nodeField
};
