import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { version } = require("../package.json");

const parseArgs = ({ args }) => {
  const options = {
    output: "./build-info.json"
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--output") {
      options.output = args[i + 1];
      i++;
    }
  }

  return options;
};

const readFirstExisting = ({ paths }) => {
  for (const filePath of paths) {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, "utf8").trim();
    }
  }

  return "";
};

const resolveGitDir = ({ cwd }) => {
  const gitPath = path.join(cwd, ".git");

  if (!fs.existsSync(gitPath)) {
    return null;
  }

  const stat = fs.statSync(gitPath);
  if (stat.isDirectory()) {
    return gitPath;
  }

  const content = fs.readFileSync(gitPath, "utf8").trim();
  const match = content.match(/^gitdir:\s*(.+)$/);
  return match ? path.resolve(cwd, match[1]) : null;
};

const readPackedRef = ({ gitDir, ref }) => {
  const packedRefsPath = path.join(gitDir, "packed-refs");
  if (!fs.existsSync(packedRefsPath)) {
    return "";
  }

  const lines = fs.readFileSync(packedRefsPath, "utf8").split(/\r?\n/);
  const match = lines.find((line) => line.endsWith(` ${ref}`));
  return match ? match.split(" ")[0] : "";
};

const resolveBuildHash = ({ cwd }) => {
  const gitDir = resolveGitDir({ cwd });
  if (!gitDir) {
    return process.env.BUILD_HASH || "unknown";
  }

  const head = readFirstExisting({
    paths: [path.join(gitDir, "HEAD")]
  });

  if (!head) {
    return process.env.BUILD_HASH || "unknown";
  }

  if (!head.startsWith("ref:")) {
    return head.slice(0, 12);
  }

  const ref = head.replace(/^ref:\s*/, "");
  const refValue = readFirstExisting({
    paths: [path.join(gitDir, ref)]
  }) || readPackedRef({ gitDir, ref });

  return refValue ? refValue.slice(0, 12) : (process.env.BUILD_HASH || "unknown");
};

const main = () => {
  const options = parseArgs({
    args: process.argv.slice(2)
  });
  const buildInfo = {
    version,
    buildHash: resolveBuildHash({
      cwd: path.resolve(import.meta.dirname, "..")
    })
  };

  fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(buildInfo, null, 2)}\n`, "utf8");
};

main();
