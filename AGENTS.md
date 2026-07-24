# AGENTS.md — keyring-actions

> `keyring-actions` is the **GitHub Action that injects Keyring secrets into CI workflows** for
> the `appleby.cloud` ecosystem. It is the CI-native equivalent of `go-keyring` / `keyring-js`:
> at the start of a workflow it authenticates to `keyring-api` with a service token, fetches the
> secrets that token is granted, and hands them to the rest of the job as **masked environment
> variables, an output JSON blob, a `KEY=value` build-args string, and a key-name list**. Instead
> of storing dozens of individual `secrets.*` values in GitHub, a repo stores one Keyring token
> and pulls everything else at runtime. This file orients any agent/worker before touching code
> in this repo.
>
> **⚠️ Golden rule — keep this file current:** any change that alters the `action.yml` contract
> (inputs/outputs), the Keyring endpoint or auth scheme, the build tooling, the masking
> behaviour, or the release/versioning process MUST update this AGENTS.md in the SAME change.
> Stale context here misleads every future agent and every consuming workflow.
>
> **⚠️ `dist/index.js` is the shipped artifact — not `src/`.** GitHub Actions runs
> `dist/index.js` (see `runs.main` in `action.yml`), never `src/index.js`. `dist/` is a
> **committed build output**. If you change anything under `src/` you MUST run `npm run build`
> and **commit the regenerated `dist/`** in the same change, or the action ships stale code and
> your edit has zero effect on any workflow. This is the single most common way to "fix" this
> action and have nothing happen.
>
> **⚠️ This action handles plaintext secret values. Masking is mandatory, not optional.**
> Every value that leaves `keyring-api` is decrypted plaintext. If it reaches a log line
> unmasked it is leaked into GitHub's build logs, which are visible to anyone with read access.
> `core.setSecret()` on every value (and on both credentials) is load-bearing security, not a
> nicety. Never remove it, never log a value, never print `secrets-json` to the console.

---

## What this repo is

A **JavaScript GitHub Action** (`runs.using: "node20"`) published from GitHub itself — there is
no npm package and no registry image. Consumers reference it by Git ref:

```yaml
uses: aidenappl/keyring-actions@v1
```

It is a **composable, single-purpose step**: given a Keyring API URL and a token
(`access-key-id` + `secret-access-key`), it calls **`GET /secrets` on `keys.appleby.cloud`**
with HTTP Basic auth, and exposes the returned secrets to the rest of the job. It does one
thing — fetch-and-inject secrets at CI time — and owns nothing else. It does **not** manage
secrets, grants, or tokens (that is `keyring-api` / `keyring-web`), and it does **not** decrypt
anything itself (`GET /secrets` returns already-decrypted values, scoped to the token's grants).

Mental model: this is `go-keyring` / `keyring-js`, re-implemented against Node's built-in
`http`/`https` so it has **zero runtime dependencies except `@actions/core`**, wrapped in the
GitHub Actions input/output contract.

## Stack & dependencies

- **Runtime:** Node 20 (pinned by `runs.using: "node20"` in `action.yml` — this is the Actions
  runner's bundled Node, not your local version). Local `node --check` on newer Node is fine for
  syntax, but the runtime target is Node 20.
- **Language:** plain CommonJS JavaScript (`require`, no ESM, no TypeScript). Note this differs
  from `keyring-mcp`, which is ESM — do not "modernise" one to match the other without reason.
- **Runtime dependency:** [`@actions/core`](https://www.npmjs.com/package/@actions/core) `^1.11.0`
  — the only production dependency. Used for `getInput`, `setSecret`, `exportVariable`,
  `setOutput`, `info`, `setFailed`. Everything else (the HTTP client) is Node built-ins
  (`http`, `https`, `Buffer`, `URL`).
- **Build tool:** [`@vercel/ncc`](https://www.npmjs.com/package/@vercel/ncc) `^0.38.0`
  (devDependency) — bundles `src/index.js` **plus all of `node_modules`** into a single
  self-contained `dist/index.js`, so the runner never runs `npm install`.
- **No tests, no linter, no framework.** `node --check` is the only static gate (see
  *Verification*).

## Project structure

| Path | Role |
|------|------|
| `action.yml` | **THE contract.** Declares metadata, `inputs`, `outputs`, and `runs` (Node 20 → `dist/index.js`). Editing this changes how every consumer calls the action. |
| `src/index.js` | The actual source (~170 lines). `fetchSecrets()` + `run()`. **This is what you edit.** |
| `dist/index.js` | **Committed build output** produced by `ncc`. ~490 KB (bundles `@actions/core`). **This is what GitHub actually runs.** Never hand-edit; always regenerate via `npm run build`. |
| `package.json` | `build` and `check` scripts; deps. `main` points at `src/index.js` (informational — the runner ignores it and uses `action.yml`). |
| `package-lock.json` | Locked dependency tree. |
| `Devfile.yaml` | The `dev` CLI commands for this repo — `build`, `release`, `install` (see below). |
| `.gitignore` | Standard Node ignores, **but explicitly does NOT ignore `dist/`** — there is a comment on line 92 saying so. Respect it. |
| `.gitattributes` | LF normalization. |
| `README.md` | Currently a stub (just the title). Worth expanding, but not load-bearing. |

There is intentionally no `.github/workflows/` and no test directory. The action is small enough
to be one source file.

## The `action.yml` contract

This is the public API of the repo. Every field below is consumed by workflows you cannot see.

### Metadata

- `name`: `"Keyring — Inject Secrets"`
- `description`: fetches secrets and injects them as env vars, outputs, and Docker build-args.
- `author`: `aidenappl`
- `branding`: `icon: lock`, `color: blue` (Marketplace styling only).

### Inputs

| Input | Required | Default | Meaning |
|-------|----------|---------|---------|
| `url` | **yes** | — | Base URL of the Keyring API, **no trailing slash** (trailing slashes are stripped anyway). The action appends `/secrets`. A bare host with no scheme is auto-prefixed with `https://` (see below). In practice this is `keys.appleby.cloud`. |
| `access-key-id` | **yes** | — | Keyring token **access key ID** (the username half of Basic auth). A secret — masked by the action itself. |
| `secret-access-key` | **yes** | — | Keyring token **secret access key** (the password half). A secret — masked by the action itself. |
| `export-env` | no | `"true"` | If not the literal string `"false"`, each fetched secret is exported as an env var (`core.exportVariable`) for **subsequent** steps. Any value other than `"false"` counts as true. |
| `mask` | no | `"true"` | If not the literal string `"false"`, each secret value is registered with `core.setSecret()` so GitHub redacts it in logs. **Only turn this off if you have an extraordinary reason — see the masking warning.** |
| `filter` | no | `""` | Comma-separated allowlist of key names to export. Empty means "all secrets the token can read". Whitespace around names is trimmed. |

Inputs are strings only (GitHub Actions has no typed inputs) — the boolean-ish inputs are
compared against the literal string `"false"`.

### Outputs

| Output | Shape | Use |
|--------|-------|-----|
| `secrets-json` | JSON object `{ "KEY": "value", ... }` of the (filtered) secrets. Values are the real plaintext, but they've been passed through `setSecret`, so GitHub masks them if they surface in logs. | `fromJSON(steps.x.outputs.secrets-json).SOME_KEY` in later steps. |
| `build-args` | Newline-delimited `KEY=value` string, keys sorted. | Feeds straight into `docker/build-push-action`'s `build-args:` input. |
| `keys` | Comma-separated list of the key **names** that were fetched (sorted). | Debugging / conditional logic; safe to print (names only, no values). |

### Runs

```yaml
runs:
  using: "node20"
  main: "dist/index.js"
```

`main` is `dist/index.js` — this is the line that makes committing `dist/` non-negotiable.

## Running, building & testing

This repo uses the `dev` CLI via `Devfile.yaml`. The commands are thin wrappers around npm:

```bash
dev install     # npm install
dev build       # npm run build  → ncc bundles src/index.js into dist/index.js
dev release      # build + commit + move v1 tag + push (see the warning below)
```

Or directly:

```bash
npm install
npm run build              # ncc build src/index.js -o dist --minify
node --check dist/index.js  # syntax-check the shipped artifact
```

- **`npm run check`** runs `node src/index.js || true` — this does almost nothing useful outside
  a runner (there are no inputs, no `GITHUB_*` env), it just proves the file loads. Real
  verification is `node --check` + a live workflow run.
- There is **no local unit-test harness.** The only faithful test is running the action inside an
  actual workflow against a real (or staging) Keyring token, or invoking `dist/index.js` with the
  Actions env vars set (`INPUT_URL`, `INPUT_ACCESS-KEY-ID`, etc.) — fiddly and rarely worth it.

### ⚠️ The `dev release` command force-pushes and moves `v1`

`Devfile.yaml`'s `release` command **runs `git push origin main` and `git push origin v1
--force`**. Per the global guardrails, **you (an agent) never push.** Do not run `dev release`.
Build and commit `dist/` if asked, then stop and let Aiden run the release. The force-moving of
the `v1` tag is how consumers on `@v1` receive updates — it is deliberate, but it is a
human-initiated action.

## How code is written here

`src/index.js` is two functions:

### `fetchSecrets(url, accessKeyId, secretAccessKey)`

- **URL normalization:** strips trailing slashes (`/\/+$/`), and if there is no `http(s)://`
  scheme it prepends `https://`. So `keys.appleby.cloud`, `https://keys.appleby.cloud`, and
  `https://keys.appleby.cloud/` all resolve to the same `https://keys.appleby.cloud/secrets`.
- **Auth:** HTTP Basic. `Authorization: Basic base64(accessKeyId + ":" + secretAccessKey)`.
  This is **exactly** how `keyring-api`'s `GET /secrets` expects credentials — the same scheme
  `go-keyring` and `keyring-js` use. Comment in the source says it "mirrors the Go and JS client
  logic exactly"; keep that true.
- **Transport:** Node built-in `http`/`https` chosen by URL scheme — no `fetch`, no `axios`, no
  dependency. This keeps the bundle tiny and the action fast.
- **Guards:** 10 s request timeout; a 32 MiB response-size cap (`MAX_BYTES = 32 << 20`) that
  destroys the request if exceeded.
- **Status handling:** `401`/`403` → a clear "unauthorized — credentials invalid or token
  inactive" error; any non-`200` → "unexpected status N"; network error/timeout → "API
  unavailable".
- **Response parsing:** expects `{ "data": [ { "key": ..., "value": ... }, ... ] }` (the standard
  Keyring `/secrets` envelope) and flattens it to `{ key: value }`. A parse failure becomes
  "malformed response from API".

### `run()`

The action lifecycle, wrapped in try/catch so any throw becomes `core.setFailed(error.message)`
(which fails the step):

1. Read the three required inputs + the three optional ones.
2. **`core.setSecret()` on both credentials immediately** — before any network call — so they
   can never surface in a log.
3. Fetch all secrets.
4. Apply the `filter` allowlist if provided.
5. **`core.setSecret()` on every value** (when `mask` is on).
6. **`core.exportVariable()` each secret** (when `export-env` is on) — makes them env vars for
   later steps.
7. Set the three outputs (`secrets-json`, `build-args`, `keys`).
8. Print a boxed summary of **key names only** (never values) and a count.

Conventions to preserve:
- **Mask before you expose.** `setSecret` is always called before `exportVariable`/`setOutput`
  for a given value. Never reorder these.
- **Log names, never values.** The summary box and the `keys` output are name-only by design.
- **Errors are strings, prefixed `keyring:`.** Keep that prefix so failures are grep-able in
  logs and consistent with the other Keyring clients.
- **No new runtime dependencies without a very good reason.** The zero-dep HTTP client is a
  feature — it keeps `dist/` small and the action cold-start-fast.

## Domain & architecture

### Where this sits

```
GitHub workflow step
      │  uses: aidenappl/keyring-actions@v1
      │  with: url, access-key-id, secret-access-key
      ▼
dist/index.js  (Node 20, on the runner)
      │  GET https://keys.appleby.cloud/secrets
      │  Authorization: Basic base64(access:secret)
      ▼
keyring-api  ──►  returns { data: [ {key, value}, ... ] }   (decrypted, grant-scoped, audited)
      │
      ▼
back in the runner: setSecret → exportVariable → setOutput
      ▼
later steps see env vars / outputs / build-args
```

### The token and its grants

The `access-key-id` / `secret-access-key` pair is a **Keyring service token** (created in
`keyring-web` / `keyring-api`). `GET /secrets` returns exactly the secrets that token has been
**granted** — nothing more. If a workflow is missing a secret it expects, the fix is almost
always **a grant in Keyring**, not a code change here. Each fetch also writes an `access_logs`
row in `keyring-api` (`grant_type: direct_token`), so a CI run is auditable there.

Store the two credential halves as **GitHub repo/org secrets** (e.g. `secrets.KEYRING_ACCESS_KEY_ID`
and `secrets.KEYRING_SECRET_ACCESS_KEY`) and pass them via `with:`. That is the one piece of
Keyring config that still lives in GitHub; everything else is pulled at runtime.

### ⚠️ The two-hostname trap

The Keyring **API** is **`keys.appleby.cloud`**. The Keyring **web dashboard** is
**`keyring.appleby.cloud`** — a *different host* (`keyring-web`). Point `url` at the web host and
you'll get a 404 on `/secrets` and a "malformed response" or "unexpected status" error. This is
the same trap documented in every Keyring repo. `url` is the API host: `keys.appleby.cloud`.

### Values are plaintext here (unlike everywhere else in Keyring)

`keyring-api` stores **ciphertext**, `keyring-mcp` **redacts**, `keyring-web` decrypts only in the
browser — but `GET /secrets` is the one path that returns **decrypted plaintext**, because that
is its whole purpose. This action therefore handles real secret values in memory. That is exactly
why masking is mandatory and why nothing here may log a value.

## Ecosystem & related repos

| Repo | Relationship |
|------|--------------|
| [`keyring-api`](https://github.com/aidenappl/keyring-api) | The API this action calls (`GET /secrets` on `keys.appleby.cloud`). Its Basic-auth scheme and `{data:[{key,value}]}` envelope are the contract this action depends on. |
| [`keyring-web`](https://github.com/aidenappl/keyring-web) | Dashboard at `keyring.appleby.cloud` (**different host**) where the token and grants used by CI are created. |
| [`keyring-js`](https://github.com/aidenappl/keyring-js) | Node/JS consumer SDK. This action deliberately re-implements the same fetch logic with zero deps rather than importing it. |
| [`go-keyring`](https://github.com/aidenappl/go-keyring) | Go consumer SDK. Same `GET /secrets` contract; this action "mirrors the Go client logic exactly". |
| [`keyring-mcp`](https://github.com/aidenappl/keyring-mcp) | MCP server for Keyring metadata (redacts values, no encryption-key tool). |
| [`forta-api`](https://github.com/aidenappl/forta-api) | Identity provider for Keyring's `/admin` surface. Not used by this action — CI auth is the Basic-auth service token, not a Forta token. |

If the `/secrets` response envelope or the Basic-auth scheme changes in `keyring-api`, this
action, `keyring-js`, and `go-keyring` all break together and must change together.

## Operations

- **"Deployment" = a Git tag/branch push.** There is no image, no npm publish, no server.
  Consumers pin `@v1` (or a commit SHA / a full version tag). The `v1` tag is a **moving
  pointer** — `dev release` force-moves it to the latest `main`, so `@v1` consumers get updates
  immediately once Aiden runs a release. This makes committing `dist/` critical: the moment the
  tag moves, whatever `dist/index.js` is committed is what runs everywhere.
- **Versioning:** consumers who want stability pin a full SHA or an immutable tag; most pin `@v1`
  for auto-updates. If you introduce a breaking change to inputs/outputs, that argues for a `v2`
  tag rather than moving `v1` — flag it for Aiden.
- **Common failure modes:**
  - *`keyring: unauthorized`* — bad/inactive token, or the credentials weren't wired through
    `with:` (empty inputs). Check the GitHub secrets and the token's status in Keyring.
  - *`keyring: unexpected status 404` / `malformed response`* — almost always `url` pointing at
    `keyring.appleby.cloud` instead of `keys.appleby.cloud`.
  - *Secret is missing from the job* — the token lacks a grant for it; fix in Keyring, not here.
  - *"I changed `src/` and nothing happened"* — `dist/` wasn't rebuilt/committed. This is the #1
    gotcha.
  - *A value appeared in the logs* — masking was off, or something logged a value directly.
    Treat as a leak; rotate the affected secret.

## Rules & guardrails

- **Never remove or weaken masking.** `core.setSecret()` on the two credentials and on every
  value is mandatory. Do not make it conditional on anything but the explicit `mask` input, and
  never log a value.
- **Never log secret values.** The summary prints **key names only**. Keep it that way. Do not
  print `secrets-json`.
- **Always rebuild and commit `dist/` when you touch `src/`** — same change, not a follow-up.
  The runner executes `dist/index.js`; an un-rebuilt `dist/` silently ships stale code.
- **Never hand-edit `dist/index.js`.** It is generated. Edit `src/`, run `npm run build`.
- **Do not push and do not run `dev release`** — it force-pushes `main` and force-moves the `v1`
  tag. That is Aiden's call. Build/commit locally at most, then stop.
- **Keep the request path exactly `GET {url}/secrets` with HTTP Basic.** It is a shared contract
  with `keyring-api`, `keyring-js`, and `go-keyring`.
- **Don't add runtime dependencies casually** — the zero-dep HTTP client is intentional.
- **Never commit real tokens or `.env` files.** Credentials come from GitHub secrets at runtime.

## Verification — always before "done"

Because there are no tests, verification is mechanical but non-negotiable:

```bash
npm install                    # if deps changed
npm run build                  # ncc → regenerates dist/index.js from src/index.js
node --check src/index.js      # source syntax
node --check dist/index.js     # SHIPPED artifact syntax — this is what runs
git status --porcelain dist/   # dist/index.js MUST show as staged/modified after a src change
git add dist/                  # stage the rebuilt artifact
```

Checklist:
1. `src/` change → `npm run build` ran → **`dist/index.js` is regenerated and staged.** If
   `git status` shows a clean `dist/` after you edited `src/`, you forgot to build.
2. `node --check dist/index.js` passes.
3. `action.yml` inputs/outputs still match what `src/index.js` reads (`core.getInput(...)`) and
   writes (`core.setOutput(...)`). A renamed input in one place and not the other silently breaks
   consumers.
4. Masking is still applied to both credentials and all values.
5. If the contract or behaviour changed, **this AGENTS.md is updated in the same change** (and
   ideally the stub `README.md` too).

**Never report work complete if `dist/` was not rebuilt after a `src/` change** — the edit will
have no effect on any workflow, which is the worst possible "done".

## Keeping this file updated

Update this AGENTS.md in the same change when you:
- **Add/rename/remove an input or output** → update the *Inputs*/*Outputs* tables. These are a
  public contract consumed by workflows you can't see.
- **Change the Keyring endpoint, auth scheme, or response-envelope handling** → update *Domain &
  architecture* and *How code is written here*; coordinate with `keyring-api`/`keyring-js`/
  `go-keyring`.
- **Change masking, filtering, or the env/output export behaviour** → update the masking
  warnings and the `run()` lifecycle description. This is the security-critical section.
- **Change the build tool or the `dist/` layout** → update the `dist/` warnings and *Verification*.
- **Change the Node version in `action.yml`** → update *Stack & dependencies*.
- **Change the release/tagging process in `Devfile.yaml`** → update *Operations* and the
  `dev release` warning.
- Also fill in `README.md` if you add a usage section — it is currently a stub.
