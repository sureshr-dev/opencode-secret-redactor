# opencode-secret-redactor

A local [OpenCode](https://opencode.ai) plugin that **detects and redacts secrets
from outbound content before it is sent to the LLM provider.** It rewrites the
system prompt and messages in place, right before each model call, so the model
and the provider never see your raw secrets. Redaction activity is logged
locally.

Everything runs on your machine. There are no network calls, no telemetry, and
no npm runtime dependencies beyond the OpenCode plugin SDK — the detection rules
are vendored into the repo.

```
you ──▶ prompt containing  AKIA...  ──▶ [secret-redactor] ──▶ provider sees  [REDACTED:aws-access-token]
```

## Why

Agentic coding tools routinely sweep environment variables, `.env` files, shell
history, and command output into the prompt. Any of that can carry a live
credential straight to a third-party LLM API. This plugin is a last line of
defence that scrubs known and well-shaped secrets out of the request body
itself, independent of what the agent decides to include.

## Requirements

- OpenCode **v2.0.x** (developed and tested against `v2.0.28`).
- The `@opencode/plugin` SDK (`^2.0.28`), installed automatically via the
  plugin's `package.json` dependency, or already present in your OpenCode config.

## Install

Clone the plugin into your OpenCode plugins directory:

```bash
git clone https://github.com/sureshr-dev/opencode-secret-redactor.git \
  ~/.config/opencode/plugins/secret-redactor
```

Then register it in `~/.config/opencode/opencode.json`:

```json
{
  "plugins": [
    {
      "package": "./plugins/secret-redactor",
      "options": {
        "env": true,
        "patterns": true,
        "log": true
      }
    }
  ]
}
```

Restart OpenCode (`opencode service restart`, or start a fresh session). On load
it writes a line to `redactor.log` in the plugin directory:

```
2026-… [secret-redactor] active — known values: N, patterns: 25
```

## How it works

The plugin registers on four session hooks exposed by `@opencode/plugin`, each of
which hands over the mutable `system` and `messages` right before a model call:

| Hook         | When it fires                                             |
| ------------ | -------------------------------------------------------- |
| `context`    | the main agent loop, including tool-driven continuations |
| `generate`   | transient `ctx.session.generate` calls                   |
| `title`      | session title generation                                 |
| `compaction` | checkpoint / summary requests                            |

On every call it deep-walks all strings in `system[]` and `messages[]` (including
nested tool-call arguments and tool-result output) and replaces any match with a
`[REDACTED:<label>]` marker. Binary payloads (`data` / `media` fields) are skipped
so they are never corrupted.

### Two detection layers

1. **Known-value matching** — the reliable layer. Exact literal values pulled
   from environment variables and an optional secrets file. A known secret is
   caught wherever it appears, in any shape.
2. **Pattern matching** — a vendored subset of the
   [Gitleaks](https://github.com/gitleaks/gitleaks) ruleset (`patterns.js`) for
   shape-based detection of unknown or rotated tokens. Only high-signal,
   prefix-anchored rules are included; the noisy `generic-api-key` rule is
   deliberately omitted to avoid false positives in live, unattended redaction.

Known values and the secrets file are re-read on **every** request, so newly
exported env vars or edits to `secrets.local` take effect without a restart.

## Configuration

Options go under `plugins[].options` in `opencode.json`:

| Option        | Type                  | Default                            | Description |
| ------------- | --------------------- | ---------------------------------- | ----------- |
| `env`         | `boolean \| string[]` | `true`                             | Redact environment variable values. `true` auto-detects names matching the secret env pattern (below). An array redacts exactly those env var names. `false` disables the env layer. |
| `secretsFile` | `string`              | `~/.config/opencode/secrets.local` | Path to a file of literal values to redact. |
| `patterns`    | `boolean`             | `true`                             | Enable the Gitleaks pattern layer. |
| `minLength`   | `number`              | `6`                                | Ignore known values shorter than this, to avoid redacting trivial strings. |
| `log`         | `boolean`             | `true`                             | Write redaction counts to `redactor.log` and the console. |

### Auto-detected env var names

When `env` is `true`, any env var whose **name** matches this pattern
(case insensitive) has its value treated as a secret:

```
_TOKEN  _KEY  _SECRET  _PAT  PASSWORD  PASSWD  _PWD  APIKEY  ACCESS_KEY
```

To redact a specific set instead, pass an array:
`"env": ["GITLAB_TOKEN", "MY_SECRET"]`.

### The secrets file

An optional plain-text file of additional literal values to redact — useful for
secrets that aren't in the environment. Default location:
`~/.config/opencode/secrets.local`. See [`secrets.local.example`](./secrets.local.example).

- One value per line.
- Blank lines and lines starting with `#` are ignored.
- Values shorter than `minLength` are skipped.

**Keep this file out of version control.** It is listed in `.gitignore`.

## Logging

With `log: true`, each model call that redacts something appends a line to
`redactor.log` in the plugin directory:

```
2026-… [secret-redactor] [context] redacted 2 occurrence(s): env:MY_TOKEN×1, pattern:github-pat×1
```

Only labels and counts are recorded — **never the secret values themselves.**

## Built-in patterns

`patterns.js` ships these 25 rules:

```
aws-access-token             gitlab-pipeline-trigger-token      databricks-api-token
aws-secret-access-key        gitlab-runner-registration-token   doppler-api-token
gcp-api-key                  slack-bot-token                    dynatrace-api-token
anthropic-api-key            slack-webhook                      age-secret-key
anthropic-admin-api-key      stripe-access-token                1password-service-account-token
openai-api-key               jwt                                atlassian-api-token
github-pat                   npm-access-token                   private-key-block
github-fine-grained-pat      pypi-upload-token
gitlab-pat                   digitalocean-pat
```

To add or adjust a rule, edit `patterns.js` (each entry is `{ id, regex }`); the
file watcher reloads it automatically.

## Performance

Redaction runs locally on already-assembled, in-memory strings — no network
round-trips. Pattern regexes are prefix-anchored, so ordinary text exits cheaply.
Measured overhead per model call:

| Prompt size              | Added latency |
| ------------------------ | ------------- |
| ~8 KB (typical turn)     | ~0.25 ms      |
| ~60 KB (medium)          | ~0.6 ms       |
| ~250 KB (large)          | ~2.2 ms       |
| ~1 MB (very large)       | ~8 ms         |

That is a tiny fraction of a single LLM round-trip (seconds), so it is not
perceptible.

## Verifying it works

1. Add a distinctive value to `~/.config/opencode/secrets.local`, e.g.
   `MY-CANARY-VALUE-123`.
2. In a new session, ask the model to repeat that exact value.
3. The model only ever receives `[REDACTED:secrets.local]`, and `redactor.log`
   records the hit.

## Limitations

- Pattern matching is shape-based: a rotated or unusually formatted secret that
  doesn't match a rule and isn't a known value will not be caught. The
  known-value layer (env + `secrets.local`) is the dependable path for anything
  you must never leak.
- Redaction applies to **model-bound content only**. It does not alter what is
  stored in local session history on disk.
- This is a safety net, not a guarantee. Rotate any credential you believe was
  exposed.

## Contributing

Issues and PRs welcome — especially new high-signal, prefix-anchored patterns.
Please do not add noisy/broad rules that would cause false positives during
unattended redaction.

## License

[MIT](./LICENSE). Vendored Gitleaks rules are also MIT licensed.
