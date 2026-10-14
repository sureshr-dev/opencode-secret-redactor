// Vendored subset of the Gitleaks ruleset (https://github.com/gitleaks/gitleaks),
// MIT licensed. Only high-signal, prefix-anchored rules with low false-positive
// rates are included. The noisy "generic-api-key" rule is intentionally omitted
// because it is unsuitable for live, unattended redaction.
//
// Each entry: { id, regex }. The regex should match the full secret token so the
// whole value is replaced. Flags are added at build time in index.js.

export const PATTERNS = [
  { id: "aws-access-token", regex: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g },
  { id: "aws-secret-access-key", regex: /\b([A-Za-z0-9/+]{40})\b(?=.*aws)/gi },
  { id: "gcp-api-key", regex: /\b(AIza[\w-]{35})\b/g },
  { id: "anthropic-api-key", regex: /\b(sk-ant-api03-[a-zA-Z0-9_-]{93}AA)\b/g },
  { id: "anthropic-admin-api-key", regex: /\b(sk-ant-admin01-[a-zA-Z0-9_-]{93}AA)\b/g },
  { id: "openai-api-key", regex: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,})\b/g },
  { id: "github-pat", regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b/g },
  { id: "github-fine-grained-pat", regex: /\b(github_pat_[0-9a-zA-Z_]{82})\b/g },
  { id: "gitlab-pat", regex: /\b(glpat-[0-9a-zA-Z_-]{20,})\b/g },
  { id: "gitlab-pipeline-trigger-token", regex: /\b(glptt-[0-9a-f]{40})\b/g },
  { id: "gitlab-runner-registration-token", regex: /\b(GR1348941[0-9a-zA-Z_-]{20,})\b/g },
  { id: "slack-bot-token", regex: /\b(xox[baprs]-[0-9a-zA-Z-]{10,})\b/g },
  { id: "slack-webhook", regex: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+)/g },
  { id: "stripe-access-token", regex: /\b((?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,})\b/g },
  { id: "jwt", regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { id: "npm-access-token", regex: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { id: "pypi-upload-token", regex: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g },
  { id: "digitalocean-pat", regex: /\b(dop_v1_[a-f0-9]{64})\b/g },
  { id: "databricks-api-token", regex: /\b(dapi[a-f0-9]{32}(?:-\d)?)\b/g },
  { id: "doppler-api-token", regex: /\b(dp\.pt\.[a-z0-9]{43})\b/gi },
  { id: "dynatrace-api-token", regex: /\b(dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64})\b/gi },
  { id: "age-secret-key", regex: /(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})/g },
  { id: "1password-service-account-token", regex: /(ops_eyJ[a-zA-Z0-9+/]{250,}={0,3})/g },
  { id: "atlassian-api-token", regex: /\b(ATATT3[A-Za-z0-9_\-=]{186})\b/g },
  { id: "private-key-block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g },
];
