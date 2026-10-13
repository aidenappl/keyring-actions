const http = require("http");
const https = require("https");

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_RETRIES = 4; // 5 attempts in total
const DEFAULT_RETRY_DELAY_MS = 2000;
const MAX_RETRY_DELAY_MS = 30000;
const MAX_BYTES = 32 << 20; // 32 MiB

// HTTP statuses that indicate a transient problem between the runner and
// keyring-api (Cloudflare 52x, gateway errors, rate limiting) — worth retrying.
// 401/403/404 and every other 4xx are permanent and fail immediately.
const RETRYABLE_STATUSES = new Set([
  408, 429, 502, 503, 504, 520, 521, 522, 523, 524,
]);

// Socket/DNS error codes that indicate a transient network failure.
const RETRYABLE_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ECONNABORTED",
  "ETIMEDOUT",
  "EPIPE",
  "EAI_AGAIN",
  "ENOTFOUND",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
]);

class KeyringError extends Error {
  constructor(message, { retryable = false, retryAfterMs = null } = {}) {
    super(message);
    this.name = "KeyringError";
    this.retryable = retryable;
    this.retryAfterMs = retryAfterMs;
  }
}

function normalizeEndpoint(url) {
  // Auto-add https:// if no protocol is present
  let normalizedUrl = url.replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = `https://${normalizedUrl}`;
  }
  return `${normalizedUrl}/secrets`;
}

// Parses a Retry-After header (seconds or HTTP date) into milliseconds.
function parseRetryAfter(value) {
  if (!value) return null;
  const secs = Number(value);
  if (Number.isFinite(secs) && secs >= 0) return secs * 1000;
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return null;
}

/**
 * Performs a single GET {url}/secrets with HTTP Basic Auth.
 * Mirrors the Go and JS client logic exactly. Rejects with a KeyringError
 * whose `retryable` flag says whether another attempt could succeed.
 */
function fetchOnce(endpoint, credentials, timeoutMs) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(endpoint);
    const transport = parsedUrl.protocol === "https:" ? https : http;
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const succeed = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    const req = transport.request(
      endpoint,
      {
        method: "GET",
        headers: { Authorization: `Basic ${credentials}` },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let byteCount = 0;

        res.on("data", (chunk) => {
          byteCount += chunk.length;
          if (byteCount > MAX_BYTES) {
            req.destroy();
            fail(new KeyringError("keyring: response body too large"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", (err) => {
          fail(
            new KeyringError(`keyring: API unavailable: ${err.message}`, {
              retryable: true,
            })
          );
        });

        res.on("aborted", () => {
          fail(
            new KeyringError("keyring: API unavailable: response aborted", {
              retryable: true,
            })
          );
        });

        res.on("end", () => {
          if (res.statusCode === 401 || res.statusCode === 403) {
            fail(
              new KeyringError(
                "keyring: unauthorized — credentials invalid or token inactive"
              )
            );
            return;
          }

          if (res.statusCode !== 200) {
            fail(
              new KeyringError(`keyring: unexpected status ${res.statusCode}`, {
                retryable: RETRYABLE_STATUSES.has(res.statusCode),
                retryAfterMs: parseRetryAfter(res.headers["retry-after"]),
              })
            );
            return;
          }

          try {
            const body = Buffer.concat(chunks).toString("utf-8");
            const payload = JSON.parse(body);
            const result = {};
            for (const s of payload.data) {
              result[s.key] = s.value;
            }
            succeed(result);
          } catch (err) {
            fail(
              new KeyringError(
                `keyring: malformed response from API: ${err.message}`
              )
            );
          }
        });
      }
    );

    req.on("error", (err) => {
      const retryable =
        RETRYABLE_CODES.has(err.code) || /socket hang up/i.test(err.message);
      fail(
        new KeyringError(`keyring: API unavailable: ${err.message}`, {
          retryable,
        })
      );
    });

    req.on("timeout", () => {
      req.destroy();
      fail(
        new KeyringError("keyring: API unavailable: request timed out", {
          retryable: true,
        })
      );
    });

    req.end();
  });
}

// Exponential backoff with "equal jitter": attempt n (1-based) waits a random
// value in [d/2, d] where d = min(base * 2^(n-1), MAX_RETRY_DELAY_MS).
function backoffDelay(attempt, baseMs, random = Math.random) {
  const ceiling = Math.min(baseMs * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS);
  return Math.round(ceiling / 2 + random() * (ceiling / 2));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Fetches secrets from the Keyring API, retrying transient failures
 * (timeouts, connection errors, 408/429/502/503/504/520-524) with
 * exponential backoff + jitter. Auth failures and other 4xx fail at once.
 *
 * `log` receives one line per retry; it never contains credentials or values.
 */
async function fetchSecrets(url, accessKeyId, secretAccessKey, opts = {}) {
  const {
    retries = DEFAULT_RETRIES,
    retryDelayMs = DEFAULT_RETRY_DELAY_MS,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    log = () => {},
    wait = sleep,
    random = Math.random,
  } = opts;

  const endpoint = normalizeEndpoint(url);
  const credentials = Buffer.from(
    `${accessKeyId}:${secretAccessKey}`
  ).toString("base64");
  const attempts = retries + 1;

  for (let attempt = 1; ; attempt++) {
    try {
      return await fetchOnce(endpoint, credentials, timeoutMs);
    } catch (err) {
      if (!err.retryable || attempt >= attempts) {
        if (err.retryable && attempts > 1) {
          err.message = `${err.message} (gave up after ${attempts} attempts)`;
        }
        throw err;
      }
      let delay = backoffDelay(attempt, retryDelayMs, random);
      if (err.retryAfterMs != null) {
        delay = Math.min(
          Math.max(delay, err.retryAfterMs),
          MAX_RETRY_DELAY_MS
        );
      }
      log(
        `keyring: attempt ${attempt}/${attempts} failed (${err.message}); ` +
          `retrying in ${(delay / 1000).toFixed(1)}s`
      );
      await wait(delay);
    }
  }
}

// Parses a non-negative integer action input, falling back to `fallback`
// when empty. Throws on anything else so misconfiguration is loud.
function parseIntInput(name, raw, fallback, max) {
  const value = (raw || "").trim();
  if (value === "") return fallback;
  if (!/^\d+$/.test(value) || Number(value) > max) {
    throw new Error(
      `keyring: invalid input ${name}="${value}" (expected an integer 0-${max})`
    );
  }
  return Number(value);
}

module.exports = {
  fetchSecrets,
  fetchOnce,
  backoffDelay,
  parseRetryAfter,
  parseIntInput,
  normalizeEndpoint,
  KeyringError,
  RETRYABLE_STATUSES,
  RETRYABLE_CODES,
  DEFAULT_RETRIES,
  DEFAULT_RETRY_DELAY_MS,
  MAX_RETRY_DELAY_MS,
};
