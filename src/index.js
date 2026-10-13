const core = require("@actions/core");
const {
  fetchSecrets,
  parseIntInput,
  DEFAULT_RETRIES,
  DEFAULT_RETRY_DELAY_MS,
} = require("./fetch");

async function run() {
  try {
    const url = core.getInput("url", { required: true });
    const accessKeyId = core.getInput("access-key-id", { required: true });
    const secretAccessKey = core.getInput("secret-access-key", {
      required: true,
    });

    // Mask the credentials themselves
    core.setSecret(accessKeyId);
    core.setSecret(secretAccessKey);

    const exportEnv = core.getInput("export-env") !== "false";
    const shouldMask = core.getInput("mask") !== "false";
    const filterRaw = core.getInput("filter").trim();
    const retries = parseIntInput(
      "retries",
      core.getInput("retries"),
      DEFAULT_RETRIES,
      10
    );
    const retryDelayMs = parseIntInput(
      "retry-delay-ms",
      core.getInput("retry-delay-ms"),
      DEFAULT_RETRY_DELAY_MS,
      30000
    );

    core.info("keyring: fetching secrets...");
    const allSecrets = await fetchSecrets(url, accessKeyId, secretAccessKey, {
      retries,
      retryDelayMs,
      log: (msg) => core.warning(msg),
    });

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
