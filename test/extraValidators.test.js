import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";
import {
  appDownloadUpdateSchema,
  dhcpReservedLeaseSchema,
  dnssecRolloverSchema,
  restoreSettingsSchema
} from "../src/extraValidators.js";
import { assertAnyLeaseIdentity } from "../src/tools/extraShared.js";

test("restore settings schema rejects path traversal file names", () => {
  const schema = z.object(restoreSettingsSchema);
  const result = schema.safeParse({
    file_name: "../backup.zip",
    confirm: true
  });

  assert.equal(result.success, false);
});

test("app update schema requires HTTPS URLs", () => {
  const schema = z.object(appDownloadUpdateSchema);
  const result = schema.safeParse({
    name: "Geo Country",
    url: "http://example.com/app.zip"
  });

  assert.equal(result.success, false);
});

test("DNSSEC rollover requires a numeric key tag and confirmation", () => {
  const schema = z.object(dnssecRolloverSchema);
  const result = schema.safeParse({
    zone: "example.com",
    key_tag: 12345,
    confirm: true
  });

  assert.equal(result.success, true);
});

test("DHCP reserved lease validates MAC and IP address values", () => {
  const schema = z.object(dhcpReservedLeaseSchema);
  const result = schema.safeParse({
    name: "Default",
    hardware_address: "not-a-mac",
    address: "192.168.1.10"
  });

  assert.equal(result.success, false);
});

test("DHCP lease identity helper requires hardware address or client identifier", () => {
  const result = assertAnyLeaseIdentity({
    args: {
      name: "Default"
    }
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "validation_error");
});
