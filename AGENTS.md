# AGENTS.md — how agents work in this repository

These rules are binding for every AI agent, automation script and contributor working on
ALHacking. They implement `SECRETS_POLICY.en.md` (English) and `SECRETS_POLICY.md` (Polish).
Read the policy before handling anything that looks like a credential.

## Default mode: mask

1. Treat every potential secret as sensitive until its nature and the user's entitlement are clear.
2. Never print, echo, quote or summarise a full secret value. Use the masked form:
   `sk-1234••••••cdef`, `AKIAEXA••••••LEEX`.
3. One-time codes (2FA, OTP, recovery codes) are never shown with any fragment, never stored, never
   repeated after the task — not in files, logs, notes or summaries.
4. Private keys: report the type header only (`-----BEGIN … PRIVATE KEY-----` + `•••••• REDACTED`).

## Ownership

| State | What you may do |
| --- | --- |
| `unknown` (default) | mask, report location and type, ask the user to establish ownership, take no other action |
| `user` (explicitly declared) | the above **plus** rotation guidance and help with clean-up; the full value only through `--reveal --ownership user --confirm-ownership … --owned-file …` |
| `third_party` | report to the owner/administrator and recommend removal/revocation; nothing else |

Never infer ownership from an account name, e-mail address, file name, domain or directory.
When in doubt, it is `unknown`.

## Never do this

- Never send a secret anywhere: no API calls to "validate" a key, no search engines, no external
  models, no paste services. The scanner in `tools/secrets/` performs no network requests by design.
- Never commit a secret, never write one to a report, log, file name, commit message, issue or PR
  description, and never include one in a screenshot or test fixture.
- Never test whether a found credential works, and never gather additional credentials around it.
- Never paste a secret the user shared back into the conversation "for confirmation".
- Never disable or bypass `.github/workflows/secrets.yml`, the `pre-commit` hook or `.secretsignore`
  entries without a recorded owner decision.
- Never add features to this repository that capture credentials from other people (phishing pages,
  fake login forms, credential loggers) or that store captured credentials. The repository installs
  third-party security tools; it must not become a credential-harvesting toolkit.

## When the user pastes a secret into the chat

1. Do not repeat it. Work with the masked form from now on.
2. Tell the user where it is exposed (chat history, screen, clipboard, ticket).
3. If it looks active, recommend immediate revocation/rotation rather than deletion of the message.
4. Point out what needs updating after rotation: CI/CD secrets, `.env`, secret manager, deployments.
5. If it ever reached git history: rotate first, then purge (`git filter-repo`/BFG).

## Working routine in this repository

```bash
# before every commit - scan what is staged
python3 tools/secrets/mask_secrets.py --git-staged --fail-on high

# full repository scan with a masked report
python3 tools/secrets/mask_secrets.py . --format markdown --out SECRETS_REPORT.md

# run the policy test-suite (no network, no writes)
python3 tools/secrets/tests/test_mask_secrets.py
```

- Install the local guard once per clone: `bash scripts/install-hooks.sh`.
- Findings must be resolved (removed from the file, moved to a secret manager, rotated) - do not
  silence them with `.secretsignore` unless the path genuinely cannot contain secrets.
- `.secretsignore` and the inline markers exist for legitimate cases only. A comment marker must be
  a real comment (`# alh-secrets: ignore-line`); mentioning a marker inside a string literal does
  not silence a file.
- The only file allowed to contain realistic-looking fake credentials is
  `tools/secrets/tests/fixtures.py`, and every value there uses invalid `EXAMPLE` filler.
  Never put a real credential in it or anywhere else in the repository.

## Reporting a finding to the user

Follow the policy's eight-step procedure and always state: type, service, location (`path:line`),
masked value, ownership status, verification status, recommended action. Never the value itself.
For a full report template see `SECRETS_REPORTS.md`.
