const core = require("@actions/core");
const http = require("http");
const https = require("https");

/**
 * Fetches secrets from the Keyring API using HTTP Basic Auth.
 * Mirrors the Go and JS client logic exactly.
 */
async function fetchSecrets(url, accessKeyId, secretAccessKey) {
  const endpoint = `${url.replace(/\/+$/, "")}/secrets`;
  const credentials = Buffer.from(
    `${accessKeyId}:${secretAccessKey}`
  ).toString("base64");

  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(endpoint);
    const transport = parsedUrl.protocol === "https:" ? https : http;

    const req = transport.request(
      endpoint,
      {
        method: "GET",
        headers: { Authorization: `Basic ${credentials}` },
        timeout: 10000,
      },
      (res) => {
        const chunks = [];
        let byteCount = 0;
        const MAX_BYTES = 32 << 20; // 32 MiB

        res.on("data", (chunk) => {
          byteCount += chunk.length;
          if (byteCount > MAX_BYTES) {
            req.destroy();
            reject(new Error("keyring: response body too large"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("end", () => {
          if (res.statusCode === 401 || res.statusCode === 403) {
            reject(
              new Error(
                "keyring: unauthorized — credentials invalid or token inactive"
              )
            );
            return;
          }

          if (res.statusCode !== 200) {
            reject(
              new Error(
                `keyring: unexpected status ${res.statusCode}`
              )
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
            resolve(result);
          } catch (err) {
            reject(
              new Error(`keyring: malformed response from API: ${err.message}`)
            );
          }
        });
      }
    );

    req.on("error", (err) => {
      reject(new Error(`keyring: API unavailable: ${err.message}`));
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("keyring: API unavailable: request timed out"));
    });

    req.end();
  });
}

async function run() {
  try {
    const url = core.getInput("url", { required: true });
    const accessKeyId = core.getInput("access-key-id", { required: true });
    const secretAccessKey = core.getInput("secret-access-key", {
      required: true,
    });
    const exportEnv = core.getInput("export-env") !== "false";
    const shouldMask = core.getInput("mask") !== "false";
    const filterRaw = core.getInput("filter").trim();

    // Mask the credentials themselves
    core.setSecret(accessKeyId);
    core.setSecret(secretAccessKey);

    core.info("keyring: fetching secrets...");
    const allSecrets = await fetchSecrets(url, accessKeyId, secretAccessKey);

    // Apply filter if provided
    let filter = null;
    if (filterRaw) {
      filter = new Set(filterRaw.split(",").map((k) => k.trim()));
    }

    const secrets = {};
    for (const [k, v] of Object.entries(allSecrets)) {
      if (filter && !filter.has(k)) continue;
      secrets[k] = v;
    }

    const keys = Object.keys(secrets).sort();

    // Mask values
    if (shouldMask) {
      for (const v of Object.values(secrets)) {
        if (v) core.setSecret(v);
      }
    }

    // Export as environment variables
    if (exportEnv) {
      for (const [k, v] of Object.entries(secrets)) {
        core.exportVariable(k, v);
      }
    }

    // Set outputs
    core.setOutput("secrets-json", JSON.stringify(secrets));

    const buildArgs = keys.map((k) => `${k}=${secrets[k]}`).join("\n");
    core.setOutput("build-args", buildArgs);

    core.setOutput("keys", keys.join(","));

    // Summary
    core.info("keyring: injected secrets");
    core.info(
      "┌──────────────────────────────────────────────────┐"
    );
    for (const k of keys) {
      core.info(`│ ${k.padEnd(48)} │`);
    }
    core.info(
      "└──────────────────────────────────────────────────┘"
    );
    core.info(`keyring: ${keys.length} secret(s) loaded`);
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
