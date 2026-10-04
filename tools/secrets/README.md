# mask_secrets — secret scanner and masker

`tools/secrets/mask_secrets.py` is the executable part of
[`SECRETS_POLICY.md`](../../SECRETS_POLICY.md) (PL) / [`SECRETS_POLICY.en.md`](../../SECRETS_POLICY.en.md) (EN).

It finds secrets in text and reports them **masked by default**:

```text
[HIGH] F-0003 openai_api_key (OpenAI)
  source: app.env:1
  value: sk-proj••••••EEXA
  verification status: pattern-match (format recognised, not validated)
  context: OPENAI_API_KEY=sk-proj••••••EEXA
  - recommended action: Revoke or rotate this credential; ... (policy 8)
```

## Guarantees

| Guarantee | How it is enforced |
| --- | --- |
| No network access, no credential validation | the module imports no HTTP/socket library; a test asserts it |
| Masked by default | every renderer uses the masked value; there is no "show all" flag |
| No secrets in files | a file is written only with `--out`, and `--out` is rejected together with `--reveal` and with machine formats |
| Full value only for the owner | `--reveal` requires `--ownership user` **and** `--confirm-ownership` **and** `--owned-file`, and applies only to the declared files, on stdout |
| Third-party secrets are never revealed | `--ownership third_party` + `--reveal` is a usage error (policy 3) |
| One-time codes are not reproducible | OTP/2FA/recovery values are masked with no prefix or suffix (policy 7) |
| No ownership guessing | the default state is `unknown` → every finding carries `ownership: unknown` and a `verify_ownership` recommendation (policy 6) |
| Nothing to disk by default | the scanner is read-only unless `--out` is given |

The scanner never reports a secret it cannot mask, and it does not store the values it finds
(they live only in the process memory for the duration of the run).

## Requirements

Python 3.8+ (the test-suite and the tool use only the standard library). No `pip install` needed.

## Quick start

```bash
# 1. scan the repository, masked text report
python3 tools/secrets/mask_secrets.py .

# 2. scan the git index (exactly what a commit would contain)
python3 tools/secrets/mask_secrets.py --git-staged --fail-on high

# 3. machine-readable reports (always masked)
python3 tools/secrets/mask_secrets.py . --format json    --out secrets.json
python3 tools/secrets/mask_secrets.py . --format sarif   --out secrets.sarif   # GitHub code scanning
python3 tools/secrets/mask_secrets.py . --format markdown --out SECRETS_REPORT.md --lang pl

# 4. pipe material in (nothing is written anywhere)
git show HEAD~1 | python3 tools/secrets/mask_secrets.py --stdin

# 5. list every detection rule
python3 tools/secrets/mask_secrets.py --list-rules
```

Exit codes: `0` nothing at/above the threshold, `1` findings at/above the threshold,
`2` usage error (including an unauthorised `--reveal` attempt).

## Options

| Option | Meaning |
| --- | --- |
| `paths…` | files or directories to scan (default: `.`) |
| `--stdin` | read the material from standard input |
| `--git-staged` | scan the content staged in the git index |
| `--format {text,json,markdown,sarif}` | report format (default `text`) |
| `--out FILE` | write the report to a file (masked output only; never with `--reveal`) |
| `--lang {en,pl}` | language of the report text (machine-readable keys stay English) |
| `--fail-on {none,medium,high,critical}` | lowest severity that makes the tool exit with `1` (default `high`) |
| `--ownership {unknown,user,third_party}` | ownership state of the scanned material (default `unknown`) |
| `--owned-file PATH` | declare a file as owned by the user (repeatable) |
| `--confirm-ownership TEXT` | the ownership statement, recorded in the report |
| `--reveal` | print full values for declared owned files (policy 2 — see below) |
| `--ignore-file FILE` | use a specific ignore file instead of `.secretsignore` |
| `--no-ignore-file` | do not honour any ignore file |
| `--max-file-size BYTES` | skip larger files (default 2 MiB) |
| `--mask-char CHAR` | masking character (default `•`) |
| `--root DIR` | base for relative locations and the ignore file |
| `--list-rules` | print the detection rules and exit |
| `--version` | print the version and exit |

## Authorised disclosure (`--reveal`)

Per policy 2, a full value is printed only when **all** of these hold:

1. `--ownership user` — ownership is declared, not assumed;
2. `--confirm-ownership "<statement>"` — a non-empty statement, recorded in the report's
   `authorization` section;
3. `--owned-file <path>` — the specific file the statement covers, and only findings inside that
   file are revealed;
4. `--format text` without `--out` — the value goes to the terminal, never to a report file.

```bash
python3 tools/secrets/mask_secrets.py env/app.env scripts/deploy.sh --reveal \
  --ownership user \
  --confirm-ownership "I own these files and hold the keys in them" \
  --owned-file env/app.env --owned-file scripts/deploy.sh
```

Any other combination is a usage error (exit code 2):

```bash
python3 tools/secrets/mask_secrets.py env/app.env --reveal            # error: policy 2 not satisfied
python3 tools/secrets/mask_secrets.py --ownership third_party --reveal …   # error: policy 3
python3 tools/secrets/mask_secrets.py --reveal --format json …        # error: policy 4
python3 tools/secrets/mask_secrets.py --reveal --out report.md …      # error: policy 4
```

While revealing, the tool prints a warning to stderr: values must not be pasted into chats,
tickets, logs or files.

> Note: this repository does not hold, and must never hold, credentials for systems you do not own.
> `--reveal` exists for the legitimate case of a user auditing their **own** machine or project.

## Report content

Every finding carries only policy-5 fields: `type`, `service`, `severity`, `category`,
`source` (`path:line`), `masked_value`, `snippet` (masked context), `fingerprint` (salted hash/path
based, non-reversible), `verification_status`, `ownership`, `disclosure` and `remediation` steps.
A `value` key appears only under an authorised `--reveal`, and only in the terminal report.

`verification_status` is deliberately weak:

- `pattern-match` — the value matches a well-known provider format (never confirmed remotely);
- `unverified` — heuristic match (generic assignment, connection string, licence key, OTP).

`fingerprint` = `sha256(path | rule-id | masked-value)[:16]`; it allows deduplication across runs
without enabling a brute-force check against short values.

## Ignoring paths and lines

`.secretsignore` (gitignore-like, resolved from the git root and from each scanned directory):

```gitignore
*.pem
secrets/
!sample.env          # negation works
```

Inline markers, only when written as a comment:

```python
API_KEY = "…"          # alh-secrets: ignore-line
# alh-secrets: ignore-next-line
API_KEY = "…"
```

```text
# alh-secrets: ignore-file
```

`gitleaks:allow` and `pragma: allowlist secret` are honoured as trailing comments too. A marker
that merely appears inside a string literal does **not** silence anything — a whole-file skip has
to be a real comment.

## Detection rules

Run `--list-rules` for the exact list. Highlights:

- private keys (PEM/OpenSSH/PGP headers, serialised key material, GCP service accounts),
- AI providers (OpenAI, Anthropic, Hugging Face),
- cloud (AWS access keys and secrets, Google API keys, Azure Storage keys and SAS, DigitalOcean),
- code hosting and CI (GitHub, GitLab, npm, PyPI, SonarQube),
- messaging and SaaS (Slack, Discord, Telegram, SendGrid, Stripe, Mailgun, Notion, Shopify, Grafana),
- generic (JWT, bearer tokens, credentials in URIs, session tokens, licence keys, password/secret
  assignments — placeholder- and entropy-filtered),
- one-time codes: OTP, 2FA and recovery codes, masked with no fragment.

Adding a rule means adding a `Rule(...)` entry and a test in
`tools/secrets/tests/test_mask_secrets.py`; the policy requires both.

## Skipped files

Binary files (NUL byte), known binary extensions, files larger than `--max-file-size`, directories
such as `.git`, `node_modules`, `vendor`, `dist`, `build`, `__pycache__`, and anything matched by the
ignore files. Skipped paths are listed in the report under `scan.skipped`.

## Integration

```bash
# local guard: install the pre-commit hook (configures core.hooksPath)
bash scripts/install-hooks.sh

# CI: .github/workflows/secrets.yml runs the scanner and the test-suite on every push/PR
# GitHub code scanning: upload the SARIF report produced with --format sarif
```

Deeper history scanning (commits, branches, tags) is intentionally **not** implemented here; use
`gitleaks` with the provided [`.gitleaks.toml`](../../.gitleaks.toml). Rotate anything that history
scanning finds — a rewritten history does not un-reveal a secret.

## Tests

```bash
python3 tools/secrets/tests/test_mask_secrets.py
```

The 45 tests encode the policy clauses: masking lengths, OTP handling, placeholder filtering,
reveal gating, "no secret in any report", ignore semantics, exit codes and the absence of network
code. Nothing in the suite performs network requests or writes outside its temporary directories.

## Limitations

- It is a pattern scanner: absence of findings is **not** proof that no secret is present.
- It does not validate credentials (by design) and does not scan git history (use gitleaks).
- Encrypted or binary blobs (keystores, dumps, images) are skipped — a screenshot with a token will
  not be caught.
- Entropy filtering inevitably trades recall for precision; treat medium/heuristic findings as
  "review this", not as confirmed leaks.
