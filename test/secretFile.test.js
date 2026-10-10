import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { reserveSecretFile } from "../src/secretFile.js";

const withTempDir = async (fn) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "technitium-secret-file-"));
  try {
    await fn(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
};

test("secret file reservation commits with mode 0600 without exposing content in metadata", async () => {
  await withTempDir(async (root) => {
    const reservation = reserveSecretFile({
      directory: root,
      fileName: "homepage-token"
    });

    const result = reservation.commit({ value: "synthetic-secret-token" });
    const stat = fs.statSync(result.filePath);

    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(result.filePath, "utf8"), "synthetic-secret-token");
    assert.deepEqual(Object.keys(result).sort(), ["fileName", "filePath", "written"]);
    assert.equal(JSON.stringify(result).includes("synthetic-secret-token"), false);
  });
});

test("secret file reservation refuses overwrite", async () => {
  await withTempDir(async (root) => {
    fs.writeFileSync(path.join(root, "existing"), "preserve-me", { mode: 0o600 });

    assert.throws(() => reserveSecretFile({
      directory: root,
      fileName: "existing"
    }), /exists|EEXIST/i);

    assert.equal(fs.readFileSync(path.join(root, "existing"), "utf8"), "preserve-me");
  });
});

test("secret file reservation abort removes an empty reservation", async () => {
  await withTempDir(async (root) => {
    const reservation = reserveSecretFile({
      directory: root,
      fileName: "aborted"
    });

    reservation.abort();
    assert.equal(fs.existsSync(path.join(root, "aborted")), false);
  });
});

test("secret file reservation rejects traversal even without schema validation", async () => {
  await withTempDir(async (root) => {
    assert.throws(() => reserveSecretFile({
      directory: root,
      fileName: "../escape"
    }), /outside|file name/i);
  });
});

test("secret output root refuses symlink redirection before writing a file", async () => {
  await withTempDir(async (root) => {
    const destination = path.join(root, "destination");
    const link = path.join(root, "linked-secret-root");
    fs.mkdirSync(destination);
    const previousMode = fs.statSync(destination).mode & 0o777;
    fs.symlinkSync(destination, link, "dir");

    assert.throws(() => reserveSecretFile({
      directory: link,
      fileName: "token-value"
    }), /symbolic link|symlink|not a regular directory/i);

    assert.equal(fs.existsSync(path.join(destination, "token-value")), false);
    assert.equal(fs.statSync(destination).mode & 0o777, previousMode);
  });
});
