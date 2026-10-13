const { test } = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  fetchSecrets,
  backoffDelay,
  parseRetryAfter,
  parseIntInput,
  normalizeEndpoint,
  MAX_RETRY_DELAY_MS,
} = require("../src/fetch");

const ACCESS = "test-access-key-id";
const SECRET = "test-secret-access-key";
const OK_BODY = JSON.stringify({
  data: [
    { key: "DB_URL", value: "mysql://value-one" },
    { key: "API_KEY", value: "value-two" },
  ],
});

// Starts a server whose Nth request (0-based) is handled by handlers[N]
// (the last handler repeats). Returns { url, count(), close() }.
async function serve(handlers) {
  let n = 0;
  const server = http.createServer((req, res) => {
    const h = handlers[Math.min(n, handlers.length - 1)];
    n++;
    h(req, res);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    count: () => n,
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(r);
      }),
  };
}

const status = (code, headers = {}) => (req, res) => {
  res.writeHead(code, headers);
  res.end("error");
};
const ok = (req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(OK_BODY);
};
const hang = () => {}; // never responds → client timeout
const hangUp = (req) => req.socket.destroy(); // socket hang up / ECONNRESET

function opts(extra = {}) {
  const logs = [];
  const waits = [];
  return {
    logs,
    waits,
    o: {
      retries: 4,
      retryDelayMs: 2000,
      timeoutMs: 200,
      log: (m) => logs.push(m),
      wait: async (ms) => waits.push(ms),
      random: () => 1,
      ...extra,
    },
  };
}

test("succeeds first time without retrying", async () => {
  const s = await serve([ok]);
  const { logs, o } = opts();
  try {
    const got = await fetchSecrets(s.url, ACCESS, SECRET, o);
    assert.deepStrictEqual(got, {
      DB_URL: "mysql://value-one",
      API_KEY: "value-two",
    });
    assert.strictEqual(s.count(), 1);
    assert.strictEqual(logs.length, 0);
  } finally {
    await s.close();
  }
});

test("sends HTTP Basic auth to {url}/secrets", async () => {
  let seen;
  const s = await serve([
    (req, res) => {
      seen = { url: req.url, auth: req.headers.authorization };
      ok(req, res);
    },
  ]);
  try {
    await fetchSecrets(s.url + "/", ACCESS, SECRET, opts().o);
    assert.strictEqual(seen.url, "/secrets");
    assert.strictEqual(
      seen.auth,
      "Basic " + Buffer.from(`${ACCESS}:${SECRET}`).toString("base64")
    );
  } finally {
    await s.close();
  }
});

for (const code of [408, 429, 502, 503, 504, 520, 521, 522, 523, 524]) {
  test(`retries HTTP ${code} then succeeds`, async () => {
    const s = await serve([status(code), status(code), ok]);
    const { logs, waits, o } = opts();
    try {
      const got = await fetchSecrets(s.url, ACCESS, SECRET, o);
      assert.strictEqual(got.API_KEY, "value-two");
      assert.strictEqual(s.count(), 3);
      assert.strictEqual(logs.length, 2);
      assert.deepStrictEqual(waits, [2000, 4000]);
      assert.match(logs[0], new RegExp(`attempt 1/5 failed .*${code}`));
    } finally {
      await s.close();
    }
  });
}

for (const code of [400, 401, 403, 404, 500]) {
  test(`does not retry HTTP ${code}`, async () => {
    const s = await serve([status(code)]);
    const { logs, o } = opts();
    try {
      await assert.rejects(fetchSecrets(s.url, ACCESS, SECRET, o), (err) => {
        if (code === 401 || code === 403) {
          assert.match(err.message, /unauthorized/);
        } else {
          assert.match(err.message, new RegExp(`unexpected status ${code}$`));
        }
        return true;
      });
      assert.strictEqual(s.count(), 1);
      assert.strictEqual(logs.length, 0);
    } finally {
      await s.close();
    }
  });
}

test("does not retry a malformed 200 response", async () => {
  const s = await serve([
    (req, res) => {
      res.writeHead(200);
      res.end("<html>not json</html>");
    },
  ]);
  try {
    await assert.rejects(
      fetchSecrets(s.url, ACCESS, SECRET, opts().o),
      /malformed response/
    );
    assert.strictEqual(s.count(), 1);
  } finally {
    await s.close();
  }
});

test("gives up after retries+1 attempts and says so", async () => {
  const s = await serve([status(522)]);
  const { logs, waits, o } = opts();
  try {
    await assert.rejects(
      fetchSecrets(s.url, ACCESS, SECRET, o),
      /unexpected status 522 \(gave up after 5 attempts\)/
    );
    assert.strictEqual(s.count(), 5);
    assert.strictEqual(logs.length, 4);
    // 2s, 4s, 8s, 16s with random()=1
    assert.deepStrictEqual(waits, [2000, 4000, 8000, 16000]);
  } finally {
    await s.close();
  }
});

test("retries=0 makes exactly one attempt", async () => {
  const s = await serve([status(503)]);
  const { o } = opts({ retries: 0 });
  try {
    await assert.rejects(
      fetchSecrets(s.url, ACCESS, SECRET, o),
      /unexpected status 503$/
    );
    assert.strictEqual(s.count(), 1);
  } finally {
    await s.close();
  }
});

test("retries a request timeout", async () => {
  const s = await serve([hang, ok]);
  const { logs, o } = opts({ timeoutMs: 100 });
  try {
    const got = await fetchSecrets(s.url, ACCESS, SECRET, o);
    assert.strictEqual(got.DB_URL, "mysql://value-one");
    assert.strictEqual(s.count(), 2);
    assert.match(logs[0], /request timed out/);
  } finally {
    await s.close();
  }
});

test("retries a socket hang up", async () => {
  const s = await serve([hangUp, ok]);
  const { logs, o } = opts();
  try {
    await fetchSecrets(s.url, ACCESS, SECRET, o);
    assert.strictEqual(s.count(), 2);
    assert.match(logs[0], /socket hang up|ECONNRESET/);
  } finally {
    await s.close();
  }
});

test("retries ECONNREFUSED", async () => {
  const s = await serve([ok]);
  const url = s.url;
  await s.close(); // nothing listening on that port any more
  const { logs, o } = opts({ retries: 2 });
  await assert.rejects(
    fetchSecrets(url, ACCESS, SECRET, o),
    /ECONNREFUSED.*\(gave up after 3 attempts\)/
  );
  assert.strictEqual(logs.length, 2);
});

test("honours Retry-After, capped at 30s", async () => {
  const s = await serve([
    status(429, { "Retry-After": "7" }),
    status(503, { "Retry-After": "120" }),
    ok,
  ]);
  const { waits, o } = opts({ retryDelayMs: 1000 });
  try {
    await fetchSecrets(s.url, ACCESS, SECRET, o);
    assert.deepStrictEqual(waits, [7000, MAX_RETRY_DELAY_MS]);
  } finally {
    await s.close();
  }
});

test("retry log lines never contain credentials or values", async () => {
  const s = await serve([status(502), hangUp, ok]);
  const { logs, o } = opts();
  try {
    await fetchSecrets(s.url, ACCESS, SECRET, o);
    const all = logs.join("\n");
    for (const needle of [
      ACCESS,
      SECRET,
      Buffer.from(`${ACCESS}:${SECRET}`).toString("base64"),
      "value-one",
      "value-two",
    ]) {
      assert.ok(!all.includes(needle), `log leaked ${needle}`);
    }
  } finally {
    await s.close();
  }
});

test("backoffDelay grows exponentially with jitter and caps at 30s", () => {
  assert.strictEqual(backoffDelay(1, 2000, () => 0), 1000);
  assert.strictEqual(backoffDelay(1, 2000, () => 1), 2000);
  assert.strictEqual(backoffDelay(3, 2000, () => 1), 8000);
  assert.strictEqual(backoffDelay(5, 2000, () => 1), 30000);
  assert.strictEqual(backoffDelay(10, 2000, () => 0), 15000);
  for (let i = 0; i < 100; i++) {
    const d = backoffDelay(2, 2000);
    assert.ok(d >= 2000 && d <= 4000, `delay ${d} out of range`);
  }
});

test("parseRetryAfter handles seconds, dates and junk", () => {
  assert.strictEqual(parseRetryAfter("5"), 5000);
  assert.strictEqual(parseRetryAfter(undefined), null);
  assert.strictEqual(parseRetryAfter("soon"), null);
  const future = new Date(Date.now() + 10000).toUTCString();
  const ms = parseRetryAfter(future);
  assert.ok(ms > 8000 && ms <= 10000, `got ${ms}`);
});

test("parseIntInput validates", () => {
  assert.strictEqual(parseIntInput("retries", "", 4, 10), 4);
  assert.strictEqual(parseIntInput("retries", " 0 ", 4, 10), 0);
  assert.strictEqual(parseIntInput("retries", "7", 4, 10), 7);
  for (const bad of ["-1", "1.5", "abc", "11"]) {
    assert.throws(() => parseIntInput("retries", bad, 4, 10), /invalid input/);
  }
});

test("normalizeEndpoint adds https and strips trailing slashes", () => {
  assert.strictEqual(
    normalizeEndpoint("keys.appleby.cloud/"),
    "https://keys.appleby.cloud/secrets"
  );
  assert.strictEqual(
    normalizeEndpoint("http://localhost:8000//"),
    "http://localhost:8000/secrets"
  );
});

// End-to-end against the SHIPPED bundle: proves dist/ was rebuilt and that
// masking still happens through the Actions command protocol.
test("dist/index.js retries, masks and exports end-to-end", async () => {
  const s = await serve([status(522), ok]);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyring-actions-"));
  const envFile = path.join(dir, "env");
  const outFile = path.join(dir, "out");
  fs.writeFileSync(envFile, "");
  fs.writeFileSync(outFile, "");
  try {
    const child = await new Promise((resolve) => {
      const { spawn } = require("node:child_process");
      const p = spawn(
        process.execPath,
        [path.join(__dirname, "..", "dist", "index.js")],
        {
          env: {
            PATH: process.env.PATH,
            GITHUB_ENV: envFile,
            GITHUB_OUTPUT: outFile,
            INPUT_URL: s.url,
            "INPUT_ACCESS-KEY-ID": ACCESS,
            "INPUT_SECRET-ACCESS-KEY": SECRET,
            "INPUT_RETRY-DELAY-MS": "10",
          },
        }
      );
      let stdout = "";
      p.stdout.on("data", (d) => (stdout += d));
      p.on("close", (code) => resolve({ code, stdout }));
    });
    assert.strictEqual(child.code, 0, child.stdout);
    assert.strictEqual(s.count(), 2);
    for (const v of [ACCESS, SECRET, "mysql://value-one", "value-two"]) {
      assert.ok(
        child.stdout.includes(`::add-mask::${v}`),
        `missing mask for a value`
      );
    }
    assert.match(child.stdout, /::warning::keyring: attempt 1\/5 failed/);
    assert.match(child.stdout, /2 secret\(s\) loaded/);
    assert.match(fs.readFileSync(envFile, "utf8"), /DB_URL/);
    assert.match(fs.readFileSync(outFile, "utf8"), /keys/);
  } finally {
    await s.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("dist/index.js rejects an invalid retries input", () => {
  const r = spawnSync(
    process.execPath,
    [path.join(__dirname, "..", "dist", "index.js")],
    {
      env: {
        PATH: process.env.PATH,
        INPUT_URL: "http://127.0.0.1:9",
        "INPUT_ACCESS-KEY-ID": ACCESS,
        "INPUT_SECRET-ACCESS-KEY": SECRET,
        INPUT_RETRIES: "lots",
      },
      encoding: "utf8",
    }
  );
  assert.match(r.stdout, /::error::keyring: invalid input retries="lots"/);
  assert.ok(r.stdout.indexOf(`::add-mask::${SECRET}`) < r.stdout.indexOf("::error::"));
});
