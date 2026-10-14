import { Plugin } from "@opencode/plugin"
import { readFileSync, appendFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { PATTERNS } from "./patterns.js"

// ---------------------------------------------------------------------------
// Secret Redactor (opencode V2 plugin, @opencode/plugin)
//
// Scrubs secrets from the outbound content before it is sent to the LLM
// provider. Two detection layers:
//   1. Known-value matching: exact literal values pulled from environment
//      variables and an optional ~/.config/opencode/secrets.local file. This
//      is the reliable layer and catches a known secret wherever it appears.
//   2. Pattern matching: a vendored subset of the Gitleaks ruleset for
//      shape-based detection of unknown/rotated tokens.
//
// It redacts at the session request hooks, which expose structured, mutable
// system prompt + messages right before the model is called:
//   - context     : the agent loop (including tool-driven continuations)
//   - generate    : transient ctx.session.generate calls
//   - title       : session title generation
//   - compaction  : checkpoint summaries
//
// Options (opencode.json plugins[].options):
//   env:         boolean | string[]  redact env var values. true => auto-detect
//                                     names matching the secret env pattern.
//                                     An array => redact exactly those env names.
//                                     Default: true.
//   secretsFile: string              path to a file of literal values to redact,
//                                     one per line (# comments allowed).
//                                     Default: ~/.config/opencode/secrets.local
//   patterns:    boolean             enable the Gitleaks pattern layer.
//                                     Default: true.
//   minLength:   number              ignore known values shorter than this.
//                                     Default: 6.
//   log:         boolean             log redaction counts to the console.
//                                     Default: true.
// ---------------------------------------------------------------------------

const SECRET_ENV_PATTERN = /(_TOKEN|_KEY|_SECRET|_PAT|PASSWORD|PASSWD|_PWD|APIKEY|ACCESS_KEY)/i
const DEFAULT_MIN_LENGTH = 6
const LOG_FILE = join(homedir(), ".config", "opencode", "plugins", "secret-redactor", "redactor.log")

function log(enabled, ...args) {
  if (!enabled) return
  const line = `[secret-redactor] ${args.join(" ")}`
  console.log(line)
  try {
    appendFileSync(LOG_FILE, `${new Date().toISOString()} ${line}\n`)
  } catch {
    // log file is best-effort; never block redaction on a write failure
  }
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function collectKnownValues(options) {
  const values = new Map() // value -> label
  const minLength = typeof options.minLength === "number" ? options.minLength : DEFAULT_MIN_LENGTH

  // Layer 1a: environment variables
  const envOpt = options.env ?? true
  if (envOpt) {
    const explicit = Array.isArray(envOpt)
    for (const [name, value] of Object.entries(process.env)) {
      if (!value || value.length < minLength) continue
      const match = explicit ? envOpt.includes(name) : SECRET_ENV_PATTERN.test(name)
      if (match) values.set(value, `env:${name}`)
    }
  }

  // Layer 1b: secrets file of literal values
  const secretsPath =
    options.secretsFile || join(homedir(), ".config", "opencode", "secrets.local")
  try {
    const content = readFileSync(secretsPath, "utf8")
    for (const raw of content.split(/\r?\n/)) {
      const line = raw.trim()
      if (!line || line.startsWith("#")) continue
      if (line.length < minLength) continue
      values.set(line, "secrets.local")
    }
  } catch {
    // file is optional; ignore if missing
  }

  // Sort longest-first so overlapping values redact the longer one first.
  return [...values.entries()]
    .sort((a, b) => b[0].length - a[0].length)
    .map(([value, label]) => ({ value, label, regex: new RegExp(escapeRegExp(value), "g") }))
}

// Returns { text, hits } where hits is a map of label -> count, or null hits.
function redactString(text, knownValues, usePatterns) {
  if (typeof text !== "string" || text.length === 0) return { text, hits: null }
  let out = text
  let hits = null

  // Layer 1: known literal values
  for (const { label, regex } of knownValues) {
    regex.lastIndex = 0
    if (!regex.test(out)) continue
    regex.lastIndex = 0
    out = out.replace(regex, `[REDACTED:${label}]`)
    hits ??= {}
    hits[label] = (hits[label] || 0) + 1
  }

  // Layer 2: Gitleaks patterns
  if (usePatterns) {
    for (const { id, regex } of PATTERNS) {
      regex.lastIndex = 0
      if (!regex.test(out)) continue
      regex.lastIndex = 0
      out = out.replace(regex, `[REDACTED:${id}]`)
      hits ??= {}
      hits[`pattern:${id}`] = (hits[`pattern:${id}`] || 0) + 1
    }
  }

  return { text: out, hits }
}

function mergeHits(tally, hits) {
  if (!hits) return
  for (const [k, v] of Object.entries(hits)) tally[k] = (tally[k] || 0) + v
}

// Deep-redacts every string in a value in place. Accumulates into `tally`.
function deepRedact(value, knownValues, usePatterns, tally) {
  if (typeof value === "string") {
    const { text, hits } = redactString(value, knownValues, usePatterns)
    mergeHits(tally, hits)
    return text
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      value[i] = deepRedact(value[i], knownValues, usePatterns, tally)
    }
    return value
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      // Skip binary media payloads to avoid corrupting them.
      if (key === "data" || key === "media") continue
      value[key] = deepRedact(value[key], knownValues, usePatterns, tally)
    }
    return value
  }
  return value
}

function reportTally(tally, logging, kind) {
  const total = Object.values(tally).reduce((a, b) => a + b, 0)
  if (total > 0) {
    const summary = Object.entries(tally)
      .map(([k, v]) => `${k}×${v}`)
      .join(", ")
    log(logging, `[${kind}] redacted ${total} occurrence(s): ${summary}`)
  }
}

export default Plugin.define({
  id: "secret-redactor",
  async setup(ctx) {
    const options = ctx.options || {}
    const logging = options.log ?? true
    const usePatterns = options.patterns ?? true

    const initial = collectKnownValues(options)
    log(
      logging,
      `active — known values: ${initial.length}, patterns: ${usePatterns ? PATTERNS.length : 0}`,
    )

    const makeRedactor = (kind) => (event) => {
      try {
        // Recompute each call so new env vars / secrets.local edits apply live.
        const known = collectKnownValues(options)
        const tally = {}
        if (Array.isArray(event.system)) {
          event.system = deepRedact(event.system, known, usePatterns, tally)
        }
        if (Array.isArray(event.messages)) {
          event.messages = deepRedact(event.messages, known, usePatterns, tally)
        }
        reportTally(tally, logging, kind)
      } catch (err) {
        log(logging, `${kind} redaction error (passing through):`, err?.message || err)
      }
    }

    const registrations = await Promise.all([
      ctx.session.hook("context", makeRedactor("context")),
      ctx.session.hook("generate", makeRedactor("generate")),
      ctx.session.hook("title", makeRedactor("title")),
      ctx.session.hook("compaction", makeRedactor("compaction")),
    ])

    return async () => {
      await Promise.allSettled(registrations.map((r) => r.dispose()))
    }
  },
})
