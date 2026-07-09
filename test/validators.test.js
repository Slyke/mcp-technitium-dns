import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";
import {
  dnsAddRecordSchema,
  dnsSetSettingsSchema,
  isCidr,
  isIpAddress,
  isRfc1035Domain
} from "../src/validators.js";

test("RFC 1035 domain validation rejects invalid labels", () => {
  assert.equal(isRfc1035Domain({ value: "example.com" }), true);
  assert.equal(isRfc1035Domain({ value: "bad_name.example.com" }), false);
  assert.equal(isRfc1035Domain({ value: "-bad.example.com" }), false);
});

test("IP and CIDR validation accepts IPv4 and IPv6", () => {
  assert.equal(isIpAddress({ value: "192.0.2.1" }), true);
  assert.equal(isIpAddress({ value: "2001:db8::1" }), true);
  assert.equal(isCidr({ value: "192.0.2.0/24" }), true);
  assert.equal(isCidr({ value: "2001:db8::/32" }), true);
});

test("record schema rejects unknown record parameters", () => {
  const schema = z.object(dnsAddRecordSchema);
  const result = schema.safeParse({
    domain: "example.com",
    type: "A",
    record: {
      ip_address: "192.0.2.10",
      unexpected: true
    }
  });

  assert.equal(result.success, false);
});

test("settings schema rejects unsupported setting keys", () => {
  const schema = z.object(dnsSetSettingsSchema);
  const result = schema.safeParse({
    settings: {
      forwarders: ["1.1.1.1"],
      notARealSetting: true
    }
  });

  assert.equal(result.success, false);
});
