# keyring-actions

A GitHub Action that fetches secrets from Keyring and injects them into a CI workflow as masked environment variables, outputs, and Docker build-args.

> **Keyring platform** · GitHub Action · CI secret injection

---

## Overview

`keyring-actions` is the CI-native equivalent of `go-keyring` / `keyring-js`. At the start of a
workflow it authenticates to `keyring-api` (`GET /secrets` on `keys.appleby.cloud`) using HTTP
Basic auth — `access-key-id` as the username, `secret-access-key` as the password — and pulls the
secrets that token has been granted. Instead of storing dozens of individual `secrets.*` values in
GitHub, a repo stores **one Keyring token** and fetches everything else at runtime.

Every returned value, plus both credentials, is registered with `core.setSecret()` so GitHub
redacts it in logs. The fetched secrets are then exposed to the rest of the job in four ways:

- **Environment variables** — each secret exported for subsequent steps (unless `export-env` is off).
- **`secrets-json`** output — a JSON object of the secrets, consumed via `fromJSON()`.
- **`build-args`** output — a newline-delimited `KEY=value` string ready for `docker/build-push-action`.
- **`keys`** output — a comma-separated list of the fetched key **names** (no values), safe to print.

`GET /secrets` returns already-decrypted, grant-scoped values, so this action handles real
plaintext secrets in memory — which is why masking is mandatory (see [Security](#security)).

## Usage

Store the two credential halves as GitHub repo/org secrets and pass them via `with:`:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Load Keyring secrets
        uses: aidenappl/keyring-actions@v1
        with:
          url: keys.appleby.cloud
          access-key-id: ${{ secrets.KEYRING_ACCESS_KEY_ID }}
          secret-access-key: ${{ secrets.KEYRING_SECRET_ACCESS_KEY }}

      # Subsequent steps now see each secret as an env var
      - name: Run migrations
        run: ./migrate.sh   # DATABASE_URL, etc. are in the environment
```

Feeding secrets into a Docker build via the `build-args` output:

```yaml
      - name: Load Keyring secrets
        id: keyring
        uses: aidenappl/keyring-actions@v1
        with:
          url: keys.appleby.cloud
          access-key-id: ${{ secrets.KEYRING_ACCESS_KEY_ID }}
          secret-access-key: ${{ secrets.KEYRING_SECRET_ACCESS_KEY }}
          filter: NPM_TOKEN,SENTRY_DSN   # optional allowlist

      - name: Build & push
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          build-args: ${{ steps.keyring.outputs.build-args }}
```

## Inputs

| Input | Required | Default | Meaning |
|-------|----------|---------|---------|
| `url` | **yes** | — | Base URL of the Keyring API (no trailing slash). The action appends `/secrets`; a bare host with no scheme is auto-prefixed with `https://`. In practice `keys.appleby.cloud`. |
| `access-key-id` | **yes** | — | Keyring token access key ID (the username half of Basic auth). |
| `secret-access-key` | **yes** | — | Keyring token secret access key (the password half of Basic auth). |
| `export-env` | no | `"true"` | Export each secret as an environment variable for subsequent steps. Any value other than the literal string `"false"` counts as true. |
| `mask` | no | `"true"` | Mask secret values in logs via `core.setSecret()`. Any value other than the literal string `"false"` counts as true. |
| `filter` | no | `""` | Comma-separated list of key names to export. If empty, all secrets the token can read are exported. |

## Outputs

| Output | Description |
|--------|-------------|
| `secrets-json` | JSON object of all fetched secrets (masked). Use `fromJSON()` to access individual keys. |
| `build-args` | Newline-delimited `KEY=VALUE` string ready for `docker/build-push-action`'s `build-args` input. |
| `keys` | Comma-separated list of secret key names that were fetched. |

## Security

- **Masking is mandatory.** Both credentials and every secret value are passed through
  `core.setSecret()` before they are exposed. Leave `mask` on unless you have an extraordinary
  reason; turning it off risks leaking plaintext into GitHub's build logs.
- **Values are decrypted plaintext at CI time.** `GET /secrets` is the one Keyring path that
  returns decrypted values — this action holds real secrets in memory.
- **Never log a value.** The action's summary and the `keys` output print key **names** only.
  Do not print `secrets-json` or any exported env var to the console.

## The two-hostname trap

`url` must point at the Keyring **API** — `keys.appleby.cloud` — **not** the Keyring web dashboard
at `keyring.appleby.cloud` (a different host). Pointing `url` at the web host yields a 404 on
`/secrets` and an "unexpected status" / "malformed response" error.

## Development & releasing

The action runs `dist/index.js` (see `runs.main` in `action.yml`), a committed, `ncc`-bundled
artifact — **not** `src/index.js`. If you change anything under `src/`, you must rebuild and commit
`dist/` in the same change, or the action ships stale code and your edit has no effect on any
workflow.

```bash
npm install
npm run build                 # ncc bundles src/index.js → dist/index.js
node --check dist/index.js    # syntax-check the shipped artifact
git add dist/                 # commit the regenerated bundle
```

Consumers pin `@v1`, which is a **moving tag** — releases force-move it to the latest `main`, so
`@v1` workflows pick up changes as soon as a release runs. See
[`AGENTS.md`](./AGENTS.md) for the full contract, build tooling, and release process.
