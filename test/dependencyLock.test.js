import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");

test("dependency lockfile describes current source and reviewed minimum resolution", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));

  assert.equal(lock.name, pkg.name);
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[""].version, pkg.version);
  const sdk = lock.packages["node_modules/@modelcontextprotocol/sdk"];
  const fastUri = lock.packages["node_modules/fast-uri"];
  assert.ok(sdk && fastUri);
  assert.ok(sdk.version.startsWith("1.32."), sdk.version);
  assert.ok(fastUri.version.startsWith("3.1."), fastUri.version);
  assert.ok(Number(fastUri.version.split(".")[2]) >= 8, fastUri.version);
});
