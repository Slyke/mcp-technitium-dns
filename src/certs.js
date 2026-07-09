import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const derLength = ({ length }) => {
  if (length < 128) {
    return Buffer.from([length]);
  }

  const bytes = [];
  let remaining = length;

  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

const der = ({ tag, value }) => {
  return Buffer.concat([
    Buffer.from([tag]),
    derLength({ length: value.length }),
    value
  ]);
};

const sequence = (...items) => der({ tag: 0x30, value: Buffer.concat(items) });
const set = (...items) => der({ tag: 0x31, value: Buffer.concat(items) });
const explicit = ({ tag, value }) => der({ tag: 0xa0 + tag, value });
const utf8String = ({ value }) => der({ tag: 0x0c, value: Buffer.from(String(value), "utf8") });
const ia5 = ({ tag, value }) => der({ tag, value: Buffer.from(String(value), "ascii") });
const nullValue = () => der({ tag: 0x05, value: Buffer.alloc(0) });
const octetString = ({ value }) => der({ tag: 0x04, value });
const bitString = ({ value, unusedBits = 0 }) => der({ tag: 0x03, value: Buffer.concat([Buffer.from([unusedBits]), value]) });
const boolean = ({ value }) => der({ tag: 0x01, value: Buffer.from([value ? 0xff : 0x00]) });

const integer = ({ value }) => {
  let bytes;

  if (typeof value === "bigint" || typeof value === "number") {
    let numberValue = BigInt(value);
    const out = [];

    if (numberValue === 0n) {
      out.push(0);
    }

    while (numberValue > 0n) {
      out.unshift(Number(numberValue & 0xffn));
      numberValue >>= 8n;
    }

    bytes = Buffer.from(out);
  } else {
    bytes = Buffer.from(value);
  }

  if (bytes[0] & 0x80) {
    bytes = Buffer.concat([Buffer.from([0]), bytes]);
  }

  return der({ tag: 0x02, value: bytes });
};

const oid = ({ value }) => {
  const parts = value.split(".").map((part) => Number(part));
  const encoded = [40 * parts[0] + parts[1]];

  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let remaining = part >> 7;

    while (remaining > 0) {
      stack.unshift((remaining & 0x7f) | 0x80);
      remaining >>= 7;
    }

    encoded.push(...stack);
  }

  return der({ tag: 0x06, value: Buffer.from(encoded) });
};

const utcTime = ({ date }) => {
  const year = String(date.getUTCFullYear()).slice(-2);
  const pad = (value) => String(value).padStart(2, "0");
  const rendered = `${year}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return der({ tag: 0x17, value: Buffer.from(rendered, "ascii") });
};

const algorithmIdentifier = () => {
  return sequence(
    oid({ value: "1.2.840.113549.1.1.11" }),
    nullValue()
  );
};

const commonName = ({ value }) => {
  return sequence(
    set(
      sequence(
        oid({ value: "2.5.4.3" }),
        utf8String({ value })
      )
    )
  );
};

const extension = ({ oidValue, critical = false, value }) => {
  return sequence(
    oid({ value: oidValue }),
    ...(critical ? [boolean({ value: true })] : []),
    octetString({ value })
  );
};

const extensions = () => {
  const basicConstraints = sequence(boolean({ value: false }));
  const keyUsage = bitString({
    value: Buffer.from([0xa0]),
    unusedBits: 5
  });
  const extendedKeyUsage = sequence(oid({ value: "1.3.6.1.5.5.7.3.1" }));
  const subjectAltName = sequence(
    ia5({ tag: 0x82, value: "localhost" }),
    der({ tag: 0x87, value: Buffer.from([127, 0, 0, 1]) })
  );

  return explicit({
    tag: 3,
    value: sequence(
      extension({
        oidValue: "2.5.29.19",
        critical: true,
        value: basicConstraints
      }),
      extension({
        oidValue: "2.5.29.15",
        critical: true,
        value: keyUsage
      }),
      extension({
        oidValue: "2.5.29.37",
        value: extendedKeyUsage
      }),
      extension({
        oidValue: "2.5.29.17",
        value: subjectAltName
      })
    )
  });
};

const toPem = ({ label, derValue }) => {
  const body = derValue.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
};

const generateSelfSignedCertificate = ({ commonNameValue = "mcp-technitium-dns" } = {}) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60 * 60 * 1000);
  const notAfter = new Date(now.getTime() + 3650 * 24 * 60 * 60 * 1000);
  const subject = commonName({ value: commonNameValue });
  const tbs = sequence(
    explicit({ tag: 0, value: integer({ value: 2 }) }),
    integer({ value: crypto.randomBytes(16) }),
    algorithmIdentifier(),
    subject,
    sequence(
      utcTime({ date: notBefore }),
      utcTime({ date: notAfter })
    ),
    subject,
    publicKey.export({
      type: "spki",
      format: "der"
    }),
    extensions()
  );
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(tbs);
  signer.end();
  const signature = signer.sign(privateKey);
  const certDer = sequence(
    tbs,
    algorithmIdentifier(),
    bitString({ value: signature })
  );

  return {
    cert: toPem({
      label: "CERTIFICATE",
      derValue: certDer
    }),
    key: privateKey.export({
      type: "pkcs8",
      format: "pem"
    })
  };
};

export const ensureHttpsCertificates = ({ certsDir }) => {
  const certPath = path.join(certsDir, "server.crt");
  const keyPath = path.join(certsDir, "server.key");

  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    fs.mkdirSync(certsDir, { recursive: true });
    const generated = generateSelfSignedCertificate();
    fs.writeFileSync(certPath, generated.cert, {
      encoding: "utf8",
      mode: 0o600
    });
    fs.writeFileSync(keyPath, generated.key, {
      encoding: "utf8",
      mode: 0o600
    });
  }

  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath)
  };
};
