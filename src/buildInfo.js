import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { version: packageVersion } = require("../package.json");

let cachedBuildInfo = null;

const parseBuildInfo = ({ value }) => {
  const version = typeof value?.version === "string" ? value.version.trim() : "";
  const buildHash = typeof value?.buildHash === "string" ? value.buildHash.trim() : "";
  return version && buildHash ? { version, buildHash } : null;
};

export const getBuildInfo = () => {
  if (cachedBuildInfo) {
    return cachedBuildInfo;
  }

  const candidatePaths = [
    process.env.BUILD_INFO_PATH,
    path.join(import.meta.dirname, "..", "build-info.json"),
    path.join(process.cwd(), "build-info.json")
  ].filter(Boolean);

  for (const filePath of candidatePaths) {
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
      const buildInfo = parseBuildInfo({ value: parsed });
      if (buildInfo) {
        cachedBuildInfo = buildInfo;
        return cachedBuildInfo;
      }
    } catch {
      continue;
    }
  }

  cachedBuildInfo = {
    version: packageVersion,
    buildHash: process.env.BUILD_HASH || "unknown"
  };
  return cachedBuildInfo;
};
