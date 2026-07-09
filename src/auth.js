import crypto from "node:crypto";

const hashToken = ({ token }) => {
  return crypto.createHash("sha256").update(String(token)).digest();
};

const timingSafeTokenEqual = ({ supplied, expected }) => {
  const suppliedHash = hashToken({ token: supplied });
  const expectedHash = hashToken({ token: expected });
  return crypto.timingSafeEqual(suppliedHash, expectedHash);
};

const parseAuthorizationHeader = ({ header }) => {
  if (!header) {
    return null;
  }

  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
};

export const buildTokenIndex = ({ config }) => {
  const readEntries = config.auth.readTokens.map((entry) => ({
    ...entry,
    role: "read"
  }));
  const readWriteEntries = config.auth.readWriteTokens.map((entry) => ({
    ...entry,
    role: "readwrite"
  }));

  return [...readEntries, ...readWriteEntries];
};

export const authenticateBearerToken = ({ token, config }) => {
  if (!token) {
    return {
      ok: false,
      status: 401,
      error: "Missing bearer token."
    };
  }

  for (const entry of buildTokenIndex({ config })) {
    if (timingSafeTokenEqual({ supplied: token, expected: entry.token })) {
      return {
        ok: true,
        identity: {
          name: entry.name,
          role: entry.role,
          scopes: entry.role === "readwrite" ? ["read", "write"] : ["read"]
        }
      };
    }
  }

  return {
    ok: false,
    status: 403,
    error: "Invalid bearer token."
  };
};

export const authenticateHttpRequest = ({ req, config }) => {
  const authorization = req.headers.authorization;
  const token = parseAuthorizationHeader({ header: authorization });

  if (!authorization || !token) {
    return {
      ok: false,
      status: 401,
      body: {
        ok: false,
        error: {
          code: "auth_error",
          message: "Missing bearer token.",
          details: {}
        }
      }
    };
  }

  const result = authenticateBearerToken({ token, config });

  if (!result.ok) {
    return {
      ok: false,
      status: result.status,
      body: {
        ok: false,
        error: {
          code: "auth_error",
          message: result.error,
          details: {}
        }
      }
    };
  }

  return result;
};

export const hasWriteScope = ({ identity }) => {
  return identity?.role === "readwrite" || identity?.scopes?.includes("write");
};

export const mcpAuthInfoFromIdentity = ({ identity }) => {
  return {
    token: "redacted",
    clientId: identity.name,
    scopes: identity.scopes
  };
};
