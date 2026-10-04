# Secret Disclosure Policy — ALHacking

| Field | Value |
| --- | --- |
| Document | `SECRETS_POLICY.en.md` (English version) |
| Version | 1.0 |
| Date | 2026-10-04 |
| Scope | the ALHacking repository: code, documentation, agent scripts, reports, logs, communication |
| Companion documents | `SECRETS_POLICY.md` (Polish version), `AGENTS.md` (rules for agents), `tools/secrets/README.md` (tooling), `SECRETS_REPORTS.md` (report template) |
| Enforcement tool | `tools/secrets/mask_secrets.py` (scanning and masking) |

This policy applies to **every** actor in this repository: a human, an AI agent, an automation
script, the CI pipeline, and any external tool invoked as part of the work.

Treat every potential secret as sensitive until its nature and the user's entitlement are clear.

---

## 1. Purpose and overriding principle

The purpose of this policy is to make work with secrets possible (detection, clean-up, rotation,
migration to a secret manager) **without increasing the risk of disclosure**.

**Overriding principle (rule 10):**
**Help the user recover and protect their own secrets, but do not increase the risk of their
disclosure.** Agent efficiency must never mean uncontrolled disclosure of credentials.

The overriding principle settles conflicts: if a more convenient answer would require revealing
the full value of a secret and that is not necessary for the task, the disclosure does not happen.

## 2. What counts as a secret

Secrets include, among others:

| Category | Examples |
| --- | --- |
| Passwords | account, database, admin panel passwords, passwords inside connection strings |
| Session tokens | `session_id`, `csrf_token`, authenticated cookies |
| API keys | provider keys (OpenAI, AWS, GitHub, Slack, Stripe, …) |
| SSH keys | private keys, key passphrases, `authorized_keys` with privilege context |
| 2FA / OTP codes | one-time codes, TOTP, SMS codes |
| Recovery codes | backup codes, TOTP seeds |
| Licence keys | product keys, serial numbers |
| Access tokens | OAuth and refresh tokens, CI/CD tokens, webhooks |
| Credentials | login/password pairs, credentials in URIs, `.env` files, `credentials.json` |
| Private cryptographic keys | PEM, OpenSSH, PKCS#8, signing keys, keystores |
| Derived material | database dumps, logs containing tokens, screenshots with logins, config files |

Also a secret: any **information that grants access** (password-reset links, invitation codes,
private endpoints that accept data without authentication).

Merely public identifiers are **not** secrets (usernames, e-mail addresses, account IDs, public
keys, OAuth client IDs) as long as they are not combined with an authenticating value. Masking them
is not required, but they must not be presented next to secrets in a way that suggests a verified
ownership link.

## 3. Ownership of a secret — three states

Ownership is established **only** from an explicit statement by the user or from documented
entitlement — never from an account name, e-mail address, file name, domain or context.

| State | Meaning | Permitted actions |
| --- | --- | --- |
| `user` (declared owner) | The user explicitly stated they own the secret and have lawful access | Identification, masking, full value only when §4 rule 2 is satisfied, rotation, history clean-up |
| `third_party` | The secret belongs to someone else, or the owner is unknown | Reporting and recommending removal/revocation only — no use, no testing, no expansion of access |
| `unknown` (unverified — default) | Ownership has not been established | Default mode: full masking, marked as unverified, ownership question before any further step |

Ownership is declared with `--owned-file` and `--confirm-ownership` (see `tools/secrets/README.md`)
and is recorded in the report as an accountability element.

## 4. The ten rules

### Rule 1 — Minimal disclosure

Do not show the full secret by default.

Instead of:

```text
sk-1234567890abcdef
```

show:

```text
sk-1234••••••cdef
```

If a fragment is enough for identification, show only the necessary part.

Masking rules used by the tool:

| Value length | Presentation |
| --- | --- |
| ≤ 8 characters | mask only (`••••••`) — no fragment is revealed |
| 9–14 characters | first 2 characters + mask + last 2 characters |
| ≥ 15 characters | first 7 characters + mask + last 4 characters |
| one-time codes (OTP, 2FA, recovery codes) | mask only, always |
| private key blocks | type header (`-----BEGIN … PRIVATE KEY-----`) + `•••••• REDACTED` |

When in doubt, mask more, not less.

### Rule 2 — Full secret

A full secret may be presented only when **all** of the following hold:

- the user unambiguously states that they own the secret,
- the secret comes from material the user may lawfully access,
- the full value is genuinely needed to complete the task.

Do not reveal a secret merely because it appears in the document being searched.

Operationally: a full value appears only on standard output, only for files declared as owned,
only with a non-empty ownership statement, and never in a report file or a machine-readable format
(JSON/SARIF/Markdown). "Genuinely needed" means the task cannot be completed with the masked value —
for example validating key syntax during a migration to a secret manager performed by the owner.

### Rule 3 — Secrets belonging to others

If you find credentials belonging to another person, a company or an unknown owner:

- do not reveal the full value,
- do not try to use it,
- do not test whether it is valid,
- do not look for additional data that would enable access.

Instead, tell the user that a potential secret was found and recommend safely removing it,
revoking it, or handing it to the responsible administrator.

Indirect actions are forbidden as well: checking "whether the key works" by calling an API,
comparing it against public breaches, filling in missing configuration elements (key/secret pairs,
account IDs, endpoints), or publishing the secret as evidence in an issue or pull request. The
report contains only the location, type, masked value and recommendation.

### Rule 4 — Secrets in search results

Never copy secrets unnecessarily into:

- reports,
- logs,
- file names,
- titles,
- search history,
- diagnostic messages.

Use masking in reports.

Practical requirements:

- report file names never contain secret identifiers (the type and date are acceptable, e.g.
  `SECRETS_REPORT.md`, not `report-ghp_XXXX.md`),
- issue and PR titles describe the **type and location**, not the value,
- context excerpts are rewritten with masking applied — not truncated around the secret,
- never paste secrets into search engines or external services to identify a provider; identify it
  from the format and context instead.

### Rule 5 — Logging

Do not write full secrets to logs. Store this instead of the value:

- secret type,
- service name,
- source location,
- masked identifier,
- verification status.

Additionally, audit records never contain the full value even for an authorised disclosure — they
record the fact and the scope of authorisation (who, when, which file, on what basis), not the value
itself. Application and CI logs must be configured so they do not print environment variables or
`Authorization` headers (GitHub Actions masks known secrets automatically, but not values built
dynamically — therefore never build messages out of a secret).

### Rule 6 — Uncertain provenance

If you cannot establish whether a secret belongs to the user, treat it as unverified.

Do not guess the owner from an account name, e-mail address or file name alone.

In unverified mode: full masking, `ownership: unknown`, a recommendation to confirm ownership with
the system owner before acting, and no usage. The ownership question is asked once and directly;
no answer means the material stays unverified.

### Rule 7 — One-time codes

2FA, OTP and recovery codes are especially sensitive.

Do not keep them in the agent's memory.

If the user supplies such a code to accomplish a specific task, use it only within that task and do
not repeat it later without an explicit need.

Additionally: one-time codes are never written to files, reports, logs, notes or shell history and
never placed in issues or commit messages. The scanner never shows even a fragment of them (mask
only), and once the task is done the code is treated as consumed — it is not quoted in summaries.

### Rule 8 — API keys and tokens

When an API key or token is found:

1. Identify the service.
2. Mask the value.
3. Tell the user where it was found.
4. If disclosure is suspected, recommend rotating the key.
5. Do not perform operations with the key without proper entitlement and an explicit instruction.

Order matters: identifying the service **must not** mean sending the key to an API and reading the
response. Rotation is recommended whenever a secret has reached git history, a chat, a log, an
issue, a screenshot or a shared device — deleting it from the current file does not remove the
exposure from repository history or from backups.

### Rule 9 — Response to accidental disclosure

If the user pastes a secret into a conversation, do not repeat it unnecessarily.

If the secret looks active and was disclosed accidentally, recommend revoking or rotating it.

Response procedure:

1. Do not quote the value — work with the masked form.
2. Assess exposure: where the secret reached (chat, commit, log, screenshot, shared device).
3. Recommend immediate revocation or rotation instead of relying on content removal.
4. List what must be updated after rotation: CI/CD, `.env`, secret manager, deployments.
5. For exposure in git history: rotate + purge history (`git filter-repo`, BFG) + notify the
   repository owner.
6. Record the event in the repository incident log (type, location, actions, date) — without the value.

### Rule 10 — Overriding principle

**Help the user recover and protect their own secrets, but do not increase the risk of their
disclosure.**

Agent efficiency must never mean uncontrolled disclosure of credentials.

---

## 5. Hard prohibitions

The following are forbidden regardless of task context:

1. Sending a secret to any network service to "check", "validate" or identify it (including search
   engines and external models).
2. Persisting a full value in the repository, a report file, a log, a file name, a commit message,
   an issue/PR description, or in communication with anyone other than the owner.
3. Using a secret to access systems the user is not documented to be entitled to.
4. Completing and testing secrets found in user material without an explicit instruction and a
   stated basis of entitlement.
5. Collecting additional credentials "around" a found secret.
6. Putting real secrets into test fixtures, documentation examples or screenshots.
7. Disabling secret scanning or bypassing the hook/CI without a recorded decision by the repository owner.

## 6. What to do when a secret is found

```text
1. STOP             do not copy the value, do not send it anywhere
2. MASK             keep only what is needed for identification
3. IDENTIFY         type + service + location (no value)
4. ESTABLISH OWNER  user / third_party / unknown (default: unknown)
5. INFORM           the user or system owner - with a recommended action
6. RECOMMEND ROTATION  if there is any suspicion of disclosure
7. CLEAN THE SOURCE remove it from the file, consider purging git history
8. RECORD           type, location, mask, status, actions taken (no value)
```

Steps 6–7 are performed by the secret's owner or a system administrator; the agent recommends them
and — on the owner's explicit instruction, for their own secrets — helps carry them out.

## 7. How the policy is enforced technically

| Rule | Mechanism in the repository |
| --- | --- |
| 1 — minimal disclosure | masking is the default in `mask_secrets.py`; there is no "show everything" switch |
| 2 — full secret | `--reveal` requires `--ownership user`, `--confirm-ownership` and `--owned-file` at once; blocked for files and machine formats |
| 3 — third-party secrets | `--ownership third_party` forbids disclosure and offers no exploitation steps; the tool performs no network requests at all |
| 4 — reports | snippets and reports are always built from masked values; secret identifiers never reach file names |
| 5 — logging | the audit record holds type, service, location, mask and verification status |
| 6 — uncertain provenance | default `unknown` state + `verify_ownership` recommendation |
| 7 — one-time codes | full mask with no prefix or suffix, "do not store" recommendation |
| 8 — API keys | service identification, mask, location, rotation recommendation; zero validation |
| 9 — accidental disclosure | the scanner never repeats the value; reports recommend revocation and rotation |
| 10 — overriding principle | unit tests that block regressions (see `tools/secrets/tests/`) |
| all | `pre-commit` hook + CI workflow `.github/workflows/secrets.yml` |

`tools/secrets/mask_secrets.py`:

```bash
# scan the repository, masked report
python3 tools/secrets/mask_secrets.py .

# scan the content staged for commit (hook mode)
python3 tools/secrets/mask_secrets.py --git-staged --fail-on high

# write a report to a file (always masked)
python3 tools/secrets/mask_secrets.py . --format markdown --out SECRETS_REPORT.md

# full value: only for an owned file, only on stdout
python3 tools/secrets/mask_secrets.py env/app.env --reveal \
  --ownership user --confirm-ownership "I own this file" \
  --owned-file env/app.env
```

Exit codes: `0` — nothing at or above the threshold, `1` — findings at or above the threshold,
`2` — usage error (including an attempt at unauthorised disclosure). Details:
`tools/secrets/README.md`.

## 8. Exceptions, approvals and accountability

1. Disclosing a full value requires a basis: ownership confirmed by a statement (for user material)
   or a written authorisation (for organisational material — e.g. a penetration-test engagement
   covering the system).
2. A statement applies to a specific file and a specific task; it is not blanket consent.
3. Every authorised disclosure is recorded in the report (`authorization` field: request, statement,
   declared files) — without the secret value.
4. There are no exceptions to the prohibitions in §5. Instead of an exception, a different approach
   is used (working with the masked value, handing the secret to its owner through a channel the
   owner chooses).
5. When in doubt, the overriding principle decides: protect, do not expose.

## 9. Review and maintenance

- Policy review: at least quarterly or after any secret-related incident.
- Detection-rule changes: always with a test in `tools/secrets/tests/` (a rule without a test does
  not ship; a test without a rule does not either).
- Policy changes are described in git history; the Polish and English versions must stay consistent.
- New secret types (new provider, new format) are added to §2 and to the tool's rules.

## 10. Compliance

Violations include in particular: publishing a full secret value, using someone else's secret,
validating a secret over the network, storing a one-time code, skipping the rotation recommendation
after disclosure, and knowingly disabling the controls. Violations are reported to the repository
owner; when third-party data is involved, also to the owner of the affected system.
