const SECRET_KEY_PATTERN = /^(authorization|cookie|set-cookie|token|apiToken|apiKey|apiSecret|password|pass|secret|sharedSecret|shared[_-]?secret|privateKey|private[_-]?key|pem.*key|clientSecret|totp|proxyPassword|primaryNodePassword|webServiceTlsCertificatePassword|dnsTlsCertificatePassword)$/i;
const SECRET_KEY_PART_PATTERN = /(authorization|bearer|cookie|password|sharedSecret|shared[_-]?secret|privateKey|private[_-]?key|pem.*key|clientSecret|apiSecret|apiToken|totp)/i;
const STACK_KEY_PATTERN = /^(stack|stackTrace|innerErrorMessage)$/i;
const PATH_KEY_PATTERN = /(?:certificatePath|keyPath|filePath|folder|directory)$/i;
const UNIX_PATH_PATTERN = /(^|[\s"'(=])\/(?:home|root|var|etc|usr|opt|mnt|tmp|app|Users)\/[^\s"',;)]+/g;
const WINDOWS_PATH_PATTERN = /[A-Za-z]:\\[^\s"',;)]+/g;

export const sanitizeString = ({ value, extraSecrets = [] }) => {
  let sanitized = String(value ?? "");

  for (const secret of extraSecrets) {
    if (secret) {
      sanitized = sanitized.split(String(secret)).join("[REDACTED]");
    }
  }

  sanitized = sanitized.replace(/Basic\s+[A-Za-z0-9+/=]+/gi, "Basic [REDACTED]");
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]");
  sanitized = sanitized.replace(/([?&](?:token|pass|password|apiKey|apiSecret)=)[^&\s]+/gi, "$1[REDACTED]");
  sanitized = sanitized.replace(WINDOWS_PATH_PATTERN, "[REDACTED_PATH]");
  sanitized = sanitized.replace(UNIX_PATH_PATTERN, (match, prefix) => `${prefix}[REDACTED_PATH]`);

  return sanitized;
};

export const sanitizeValue = ({ value, extraSecrets = [] }) => {
  if (value === undefined || value === null) {
    return value;
  }

  if (typeof value === "string") {
    return sanitizeString({ value, extraSecrets });
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: sanitizeString({
        value: value.message,
        extraSecrets
      })
    };
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue({ value: item, extraSecrets }));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !STACK_KEY_PATTERN.test(key))
        .map(([key, nested]) => {
          if (SECRET_KEY_PATTERN.test(key) || SECRET_KEY_PART_PATTERN.test(key)) {
            return [key, "[REDACTED]"];
          }

          if (PATH_KEY_PATTERN.test(key) && typeof nested === "string" && nested) {
            return [key, "[REDACTED_PATH]"];
          }

          return [key, sanitizeValue({ value: nested, extraSecrets })];
        })
    );
  }

  return value;
};

export const sanitizeErrorMessage = ({ message, extraSecrets = [] }) => {
  const sanitized = sanitizeString({
    value: message,
    extraSecrets
  });

  return sanitized
    .replace(/\s+at\s+.+/g, "")
    .replace(/stack trace[:\s].*$/i, "stack trace [REDACTED]")
    .trim();
};
