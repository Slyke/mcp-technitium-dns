import fs from "node:fs";
import path from "node:path";

const assertSafeFileName = ({ fileName }) => {
  const value = String(fileName ?? "").trim();
  if (!value || value === "." || value === ".." || /[\\/]/.test(value) || value.includes("\0")) {
    throw new Error("Secret output file name must be a file name, not a path.");
  }
  return value;
};

const resolveChildFile = ({ directory, fileName }) => {
  const root = path.resolve(directory);
  const safeFileName = assertSafeFileName({ fileName });
  const filePath = path.resolve(root, safeFileName);

  if (!filePath.startsWith(root + path.sep)) {
    throw new Error("Secret output file resolved outside the configured directory.");
  }

  return {
    root,
    filePath,
    fileName: safeFileName
  };
};

export const reserveSecretFile = ({ directory, fileName }) => {
  const resolved = resolveChildFile({ directory, fileName });
  fs.mkdirSync(resolved.root, { recursive: true, mode: 0o700 });
  const rootInfo = fs.lstatSync(resolved.root);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    throw new Error("Secret output root must be a regular directory, not a symbolic link.");
  }
  fs.chmodSync(resolved.root, 0o700);

  const fd = fs.openSync(resolved.filePath, "wx", 0o600);
  fs.chmodSync(resolved.filePath, 0o600);
  let state = "reserved";

  const closeQuietly = () => {
    try {
      fs.closeSync(fd);
    } catch {
      // Best-effort cleanup after a failed write/abort.
    }
  };

  const unlinkQuietly = () => {
    try {
      fs.unlinkSync(resolved.filePath);
    } catch {
      // Best-effort cleanup after a failed write/abort.
    }
  };

  return {
    fileName: resolved.fileName,
    filePath: resolved.filePath,
    commit: ({ value }) => {
      if (state !== "reserved") {
        throw new Error("Secret output reservation is no longer active.");
      }

      const secret = String(value ?? "");
      if (!secret) {
        closeQuietly();
        unlinkQuietly();
        state = "aborted";
        throw new Error("Secret output value must not be empty.");
      }

      try {
        fs.writeFileSync(fd, secret, { encoding: "utf8" });
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fs.chmodSync(resolved.filePath, 0o600);
        state = "committed";
        return {
          fileName: resolved.fileName,
          filePath: resolved.filePath,
          written: true
        };
      } catch (err) {
        closeQuietly();
        unlinkQuietly();
        state = "aborted";
        throw err;
      }
    },
    abort: () => {
      if (state !== "reserved") {
        return;
      }
      closeQuietly();
      unlinkQuietly();
      state = "aborted";
    }
  };
};
