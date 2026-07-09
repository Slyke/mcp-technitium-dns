const nowMs = () => Date.now();

export const createRateLimiter = ({ config }) => {
  const buckets = new Map();

  const check = ({ identityName, toolName, category }) => {
    const limits = config.rateLimits[category] ?? config.rateLimits.read;
    if (!limits?.enabled) {
      return {
        ok: true
      };
    }

    const key = `${identityName}:${category}:${toolName}`;
    const now = nowMs();
    const existing = buckets.get(key);
    const bucket = existing && existing.resetAt > now
      ? existing
      : {
        count: 0,
        resetAt: now + limits.windowMs
      };

    bucket.count += 1;
    buckets.set(key, bucket);

    if (bucket.count > limits.max) {
      return {
        ok: false,
        retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
        limit: limits.max,
        windowMs: limits.windowMs
      };
    }

    return {
      ok: true,
      remaining: Math.max(0, limits.max - bucket.count),
      resetAt: new Date(bucket.resetAt).toISOString()
    };
  };

  return {
    check
  };
};
