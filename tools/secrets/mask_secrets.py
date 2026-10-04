#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mask_secrets.py - ALHacking secret scanner and masker.

This tool is the executable part of the disclosure policy described in
``SECRETS_POLICY.md`` (PL) and ``SECRETS_POLICY.en.md`` (EN):

* policy 1  - minimal disclosure: values are masked by default,
* policy 3  - third-party secrets: never revealed, never used, never validated,
* policy 4  - reports: masked values only, no secrets in titles or file names,
* policy 5  - logging: the audit record stores only the secret *type*, the
              service, the source location, a masked identifier and the
              verification status,
* policy 6  - unknown provenance: ownership is "unverified" unless declared,
* policy 7  - one-time codes: never printed with prefix/suffix, never stored,
* policy 8  - API keys/tokens: identify the service, mask the value, point to
              the source and recommend rotation.

Hard guarantees (enforced in code, covered by tests):

* the scanner performs **no network requests** and never validates a
  credential against a remote service,
* it writes nothing to disk unless ``--out`` is given explicitly,
* a full value is printed only when *all* of the following hold:
  ``--reveal`` + ``--ownership user`` + ``--confirm-ownership <statement>``
  + ``--owned-file <path>`` and only for findings located in the declared
  files.  ``--reveal`` is rejected together with ``--out`` and with any
  machine-readable format, so unmasked values can never end up in a report
  file (policies 2 and 4).

Exit codes: 0 = clean, 1 = findings at/above ``--fail-on``, 2 = usage error.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

VERSION = "1.0.0"
SCHEMA = "alh.secrets.report/v1"
POLICY_PL = "SECRETS_POLICY.md"
POLICY_EN = "SECRETS_POLICY.en.md"
DEFAULT_MASK_CHAR = "\u2022"  # policy 1 uses bullets: sk-1234••••••cdef
DEFAULT_IGNORE_FILE = ".secretsignore"
MASK_RUN = 6

SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}

# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    ``priority`` decides which rule wins when two patterns overlap on the same
    line: higher priority means more specific (an OpenAI key beats the generic
    ``api_key = ...`` heuristic).
    """

    id: str
    service: str
    severity: str
    category: str
    pattern: re.Pattern
    group: int = 0
    priority: int = 10
    generic: bool = False
    description: str = ""


def _r(pattern: str, **kw) -> re.Pattern:
    return re.compile(pattern, kw.pop("flags", 0))


KEYWORD = (r"\w{0,32}(?:secret|token|api[_-]?key|apikey|auth[_-]?token|oauth[_-]?token|"
           r"access[_-]?token|client[_-]?secret|refresh[_-]?token|private[_-]?token|"
           r"passwd|pwd|pass(?:word|phrase|wd|wrd)?)")

RULES: Tuple[Rule, ...] = (
    # --- private keys ------------------------------------------------------ #
    Rule(
        id="private_key_pem",
        service="Generic (PEM)",
        severity="critical",
        category="private_key",
        pattern=_r(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----"),
        priority=100,
        description="PEM/OpenSSH/PGP/SSH private key block",
    ),
    Rule(
        id="private_key_material",
        service="Generic (key material)",
        severity="critical",
        category="private_key",
        pattern=_r(r"(?i)^[\"']?(private[_-]?key|client[_-]?key[_-]?data|private_key_id|"
                   r"signing[_-]?key|certificate[_-]?key)[\"']?[\"'\s]{0,4}[:=][\"'\s]{0,4}"
                   r"([A-Za-z0-9+/=_-]{32,})"),
        group=2,
        priority=90,
        description="serialised private key material (JSON/YAML/Kubernetes config)",
    ),
    # --- AI providers ------------------------------------------------------ #
    Rule(
        id="openai_api_key",
        service="OpenAI",
        severity="high",
        category="api_key",
        pattern=_r(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
        priority=80,
        description="OpenAI API key",
    ),
    Rule(
        id="anthropic_api_key",
        service="Anthropic",
        severity="high",
        category="api_key",
        pattern=_r(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        priority=80,
        description="Anthropic API key",
    ),
    Rule(
        id="huggingface_token",
        service="Hugging Face",
        severity="high",
        category="api_key",
        pattern=_r(r"\bhf_[A-Za-z0-9]{30,}\b"),
        priority=80,
    ),
    # --- cloud ------------------------------------------------------------- #
    Rule(
        id="aws_access_key_id",
        service="AWS",
        severity="high",
        category="api_key",
        pattern=_r(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        priority=85,
    ),
    Rule(
        id="aws_secret_access_key",
        service="AWS",
        severity="critical",
        category="api_key",
        pattern=_r(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})"),
        group=1,
        priority=95,
    ),
    Rule(
        id="google_api_key",
        service="Google",
        severity="high",
        category="api_key",
        pattern=_r(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        priority=85,
    ),
    Rule(
        id="gcp_service_account_key",
        service="Google Cloud",
        severity="critical",
        category="private_key",
        pattern=_r(r"[\"']type[\"']\s*:\s*[\"']service_account[\"']"),
        priority=60,
        description="GCP service-account JSON blob (contains key material)",
    ),
    Rule(
        id="azure_storage_account_key",
        service="Azure Storage",
        severity="critical",
        category="api_key",
        pattern=_r(r"(?i)accountkey[\"'\s]{0,4}=[\"'\s]{0,4}([A-Za-z0-9+/=]{40,})"),
        group=1,
        priority=90,
    ),
    Rule(
        id="azure_sas_token",
        service="Azure SAS",
        severity="high",
        category="token",
        pattern=_r(r"(?i)\bsig=([A-Za-z0-9%]{30,})"),
        group=1,
        priority=70,
    ),
    Rule(
        id="digitalocean_token",
        service="DigitalOcean",
        severity="high",
        category="api_key",
        pattern=_r(r"\bdop_v1_[0-9a-f]{64}\b"),
        priority=85,
    ),
    # --- code hosting / CI -------------------------------------------------- #
    Rule(
        id="github_token",
        service="GitHub",
        severity="high",
        category="token",
        pattern=_r(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        priority=85,
    ),
    Rule(
        id="gitlab_token",
        service="GitLab",
        severity="high",
        category="token",
        pattern=_r(r"\bglpat-[A-Za-z0-9_-]{18,}\b"),
        priority=85,
    ),
    Rule(
        id="npm_token",
        service="npm",
        severity="high",
        category="token",
        pattern=_r(r"\bnpm_[A-Za-z0-9]{34,}\b"),
        priority=85,
    ),
    Rule(
        id="pypi_token",
        service="PyPI",
        severity="high",
        category="token",
        pattern=_r(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{10,}\b"),
        priority=85,
    ),
    Rule(
        id="sonarqube_token",
        service="SonarQube",
        severity="high",
        category="token",
        pattern=_r(r"\bsqp_[0-9a-f]{40}\b"),
        priority=85,
    ),
    # --- messaging / SaaS --------------------------------------------------- #
    Rule(
        id="slack_token",
        service="Slack",
        severity="high",
        category="token",
        pattern=_r(r"\bxox[abpros]-[A-Za-z0-9-]{10,}\b"),
        priority=85,
    ),
    Rule(
        id="slack_webhook",
        service="Slack",
        severity="high",
        category="token",
        pattern=_r(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
        priority=85,
    ),
    Rule(
        id="discord_webhook",
        service="Discord",
        severity="high",
        category="token",
        pattern=_r(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
                   r"[0-9]{15,}/[A-Za-z0-9_-]{50,}"),
        priority=85,
    ),
    Rule(
        id="telegram_bot_token",
        service="Telegram",
        severity="high",
        category="token",
        pattern=_r(r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        priority=85,
    ),
    Rule(
        id="sendgrid_api_key",
        service="SendGrid",
        severity="high",
        category="api_key",
        pattern=_r(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        priority=85,
    ),
    Rule(
        id="stripe_secret_key",
        service="Stripe",
        severity="high",
        category="api_key",
        pattern=_r(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
        priority=85,
    ),
    Rule(
        id="mailgun_api_key",
        service="Mailgun",
        severity="high",
        category="api_key",
        pattern=_r(r"\bkey-[0-9a-zA-Z]{32}\b"),
        priority=70,
    ),
    Rule(
        id="notion_token",
        service="Notion",
        severity="high",
        category="token",
        pattern=_r(r"\b(?:ntn|secret)_[A-Za-z0-9]{30,}\b"),
        priority=75,
    ),
    Rule(
        id="shopify_token",
        service="Shopify",
        severity="high",
        category="token",
        pattern=_r(r"\bshpat_[0-9a-f]{32}\b"),
        priority=85,
    ),
    Rule(
        id="grafana_token",
        service="Grafana",
        severity="high",
        category="token",
        pattern=_r(r"\bglsa_[A-Za-z0-9]{32,}_[0-9a-f]{8}\b"),
        priority=85,
    ),
    # --- generic credentials ------------------------------------------------ #
    Rule(
        id="jwt",
        service="Generic (JWT)",
        severity="high",
        category="token",
        pattern=_r(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b"),
        priority=65,
    ),
    Rule(
        id="bearer_token",
        service="Generic (bearer)",
        severity="high",
        category="token",
        pattern=_r(r"(?i)authorization[\"'\s]{0,4}[:=][\"'\s]{0,4}bearer\s+([A-Za-z0-9._~+/-]{20,}=*)"),
        group=1,
        priority=70,
    ),
    Rule(
        id="uri_with_password",
        service="Generic (connection string)",
        severity="high",
        category="uri_credentials",
        pattern=_r(r"\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@\"']{1,64}:([^/\s:@\"']{4,128})@"),
        group=1,
        priority=88,
        description="credentials embedded in a URI (postgres/mysql/mongodb/redis/amqp/ldap)",
    ),
    Rule(
        id="session_token",
        service="Generic (session)",
        severity="high",
        category="token",
        pattern=_r(r"(?i)\b(?:session|sess|csrf|xsrf)[_-]?(?:id|token|key)[\"'\s]{0,4}[:=][\"'\s]{0,4}"
                   r"([A-Za-z0-9._~+/=-]{16,})"),
        group=1,
        priority=60,
    ),
    Rule(
        id="otp_or_recovery_code",
        service="Generic (one-time code)",
        severity="critical",
        category="otp",
        pattern=_r(r"(?i)\b(?:recovery|backup|2fa|two[_-]?factor|mfa|otp|one[_-]?time|verification)"
                   r"[_-]?(?:codes?|passwords?|seeds?)?\w{0,24}?[^\d\n]{0,24}?"
                   r"(\d{4,8}(?:[-\s]\d{4,8}){0,3})\b"),
        group=1,
        priority=55,
        description="2FA / OTP / recovery code (policy 7: never stored or repeated)",
    ),
    Rule(
        id="recovery_code_block",
        service="Generic (recovery codes)",
        severity="critical",
        category="otp",
        # Any non-digit run may separate the keyword from the code groups.
        pattern=_r(r"(?i)\b(?:recovery|backup|2fa|two[_-]?factor|mfa|otp)[^\d\n]{0,40}?"
                   r"([A-Za-z0-9]{4,8}(?:[\s-][A-Za-z0-9]{4,8}){1,7})\b"),
        group=1,
        priority=54,
        description="recovery-code block written as groups (policy 7)",
    ),
    Rule(
        id="license_key",
        service="Generic (licence)",
        severity="medium",
        category="license_key",
        pattern=_r(r"(?i)\b(?:licen[cs]e|serial|product)[_-]?(?:key|code|id)[\"'\s]{0,4}[:=][\"'\s]{0,4}"
                   r"([A-Z0-9][A-Z0-9-]{11,})"),
        group=1,
        priority=58,
    ),
    Rule(
        id="credential_assignment",
        service="Generic (credential)",
        severity="medium",
        category="secret",
        pattern=_r(r"(?i)\b" + KEYWORD + r"\w{0,16}?[\"'\s]{0,4}[:=][\"'\s]{0,4}([^\s'\";,]{8,})"),
        group=1,
        priority=45,
        generic=True,
        description="credential-looking assignment (placeholder- and entropy-filtered)",
    ),
)

RULE_BY_ID = {r.id: r for r in RULES}

# A captured value containing these characters is source code, a regex or a
# template - not a credential.  Real secrets are [A-Za-z0-9._~+/=:@-].
CODE_ARTIFACT_RE = re.compile(r"[\\{}()\[\]<>|^$*?!]")

# Values that only look like credentials.  Reporting them would be noise.
TEMPLATE_RE = re.compile(
    r"""(?ix)^(?:
        x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|\?{2,}|
        <[^>]*>|\{\{?[^}]*\}?\}?|
        \$\{?[A-Za-z_][A-Za-z0-9_.]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|
        [A-Z][A-Z0-9_]{3,}
    )$"""
)

# A value made only of these tokens is a placeholder, not a credential.
PLACEHOLDER_WORDS = {
    "your", "you", "my", "the", "some", "any", "example", "examples", "sample",
    "demo", "dummy", "fake", "faux", "test", "testing", "tests", "placeholder",
    "change", "changeme", "changethis", "me", "redacted", "masked", "removed",
    "hidden", "insert", "enter", "todo", "fixme", "none", "null", "nil", "nan",
    "true", "false", "undefined", "unset", "empty", "password", "passwd", "pwd",
    "token", "key", "keys", "apikey", "api", "value", "string", "integer",
    "bool", "here", "x", "xx", "xxx", "secret", "secrets", "foo", "bar", "baz",
    "username", "user", "localhost", "process", "env", "environ", "getenv",
    "dotenv", "os", "export", "var", "variable", "attribute", "credential",
    "credentials", "sample123", "xxxx", "xxxxx", "aaaa", "abcdef", "0123456789",
}

# Refuse to scan huge blobs and obviously-binary files.
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__",
             ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".idea"}
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz",
                 ".tar", ".7z", ".rar", ".woff", ".woff2", ".ttf", ".eot", ".ico",
                 ".mp3", ".mp4", ".mov", ".so", ".dylib", ".dll", ".exe", ".class",
                 ".jar", ".pyc", ".lock", ".svg")

# Inline markers are only honoured inside comments, so that merely mentioning
# a marker in a string literal does not silence a whole file.
_COMMENT = r"(?:#|//|--|;|<!--|\*)\s*"
INLINE_IGNORE_FILE_RE = re.compile(r"(?m)^\s*" + _COMMENT + r"alh-secrets:\s*ignore-file\b")
INLINE_IGNORE_LINE_RE = re.compile(
    _COMMENT + r"(?:alh-secrets:\s*ignore-line\b|gitleaks:allow\b|"
    r"pragma:\s*allowlist\s+secret)"
)
INLINE_IGNORE_NEXT_RE = re.compile(_COMMENT + r"alh-secrets:\s*ignore-next-line\b")

# --------------------------------------------------------------------------- #
# Localisation (report strings only - machine-readable keys stay English)
# --------------------------------------------------------------------------- #

MESSAGES = {
    "en": {
        "title": "Secret scan report",
        "generated": "generated",
        "tool": "tool",
        "network": "network requests",
        "no_network_value": "none (credentials are never validated)",
        "policy": "policy",
        "ownership": "ownership",
        "scope": "scope",
        "files_scanned": "files scanned",
        "files_skipped": "files skipped",
        "findings": "findings",
        "summary": "summary",
        "total": "total",
        "no_findings": "No potential secrets detected in the scanned material.",
        "source": "source",
        "value": "value",
        "status": "verification status",
        "advice": "recommended action",
        "context": "context",
        "footer": ("Masked by default (policy 1). Nothing was transmitted, validated, or stored "
                   "outside this report (policies 3, 4, 5)."),
        "third_party_notice": ("A secret belonging to a third party was detected. Do not use it, do not "
                               "test it, do not look for further access data - report it to the "
                               "owner/administrator and remove it (policy 3)."),
        "unverified_notice": ("Ownership was not established, so every finding is treated as "
                              "unverified (policy 6)."),
        "reveal_warning": ("WARNING: --reveal prints full secret values to stdout. Do not paste them "
                           "into chats, tickets, logs or files (policies 4, 5, 9)."),
        "reveal_denied_third_party": "--reveal is not allowed with --ownership third-party (policy 3).",
        "reveal_denied_format": "--reveal is only allowed with --format text and without --out (policy 4).",
        "reveal_denied_authorization": ("--reveal requires --ownership user, a non-empty "
                                        "--confirm-ownership statement and at least one --owned-file "
                                        "(policy 2)."),
        "reveal_scope": "authorised disclosure: file declared by the owner",
        "nothing_to_scan": "nothing to scan",
    },
    "pl": {
        "title": "Raport skanowania sekretów",
        "generated": "wygenerowano",
        "tool": "narzędzie",
        "network": "zapytania sieciowe",
        "no_network_value": "brak (sekrety nie są nigdy weryfikowane)",
        "policy": "polityka",
        "ownership": "własność",
        "scope": "zakres",
        "files_scanned": "przeskanowane pliki",
        "files_skipped": "pominięte pliki",
        "findings": "znaleziska",
        "summary": "podsumowanie",
        "total": "razem",
        "no_findings": "Nie wykryto potencjalnych sekretów w przeskanowanym materiale.",
        "source": "źródło",
        "value": "wartość",
        "status": "status weryfikacji",
        "advice": "zalecane działanie",
        "context": "kontekst",
        "footer": ("Domyślne maskowanie (zasada 1). Nic nie zostało przesłane, zweryfikowane ani "
                   "zapisane poza tym raportem (zasady 3, 4, 5)."),
        "third_party_notice": ("Wykryto sekret należący do innej osoby lub firmy. Nie używaj go, nie "
                               "testuj go, nie szukaj kolejnych danych dostępowych - zgłoś go "
                               "właścicielowi/administratorowi i usuń (zasada 3)."),
        "unverified_notice": ("Nie ustalono właściciela, więc każde znalezisko jest traktowane jako "
                              "niezweryfikowane (zasada 6)."),
        "reveal_warning": ("UWAGA: --reveal wypisuje pełne wartości sekretów na standardowe wyjście. "
                           "Nie wolno ich wklejać do czatów, zgłoszeń, logów ani plików (zasady 4, 5, 9)."),
        "reveal_denied_third_party": "--reveal jest niedozwolone przy --ownership third-party (zasada 3).",
        "reveal_denied_format": "--reveal działa tylko z --format text i bez --out (zasada 4).",
        "reveal_denied_authorization": ("--reveal wymaga --ownership user, niepustego oświadczenia "
                                        "--confirm-ownership i co najmniej jednego --owned-file (zasada 2)."),
        "reveal_scope": "ujawnienie autoryzowane: plik zadeklarowany przez właściciela",
        "nothing_to_scan": "brak materiału do przeskanowania",
    },
}

OWNERSHIP_LABEL = {
    "unknown": {"en": "unverified", "pl": "niezweryfikowana"},
    "user": {"en": "declared by the user (owner)", "pl": "zadeklarowana przez użytkownika (właściciel)"},
    "third_party": {"en": "third party", "pl": "osoba trzecia"},
}

REMEDIATION = {
    "revoke_or_rotate": {
        "en": "Revoke or rotate this credential; if it was committed or shared, assume it is compromised.",
        "pl": "Unieważnij lub zrotuj ten sekret; jeśli trafił do repozytorium lub został udostępniony, "
              "przyjmij, że jest skompromitowany.",
    },
    "remove_from_source": {
        "en": "Remove it from the file and keep it in a secret manager or an environment variable "
              "outside version control.",
        "pl": "Usuń go z pliku i przenieś do menedżera sekretów lub zmiennej środowiskowej poza kontrolą "
              "wersji.",
    },
    "purge_from_history": {
        "en": "If it ever entered git history, purge it with git-filter-repo/BFG and rotate it - "
              "rewriting history alone is not enough.",
        "pl": "Jeśli sekret kiedykolwiek trafił do historii git, usuń go narzędziem git-filter-repo/BFG "
              "i zrotuj go - przepisanie historii samo w sobie nie wystarcza.",
    },
    "report_to_owner": {
        "en": "Report the finding to the system owner or administrator; do not use, test, or expand "
              "access with it (policy 3).",
        "pl": "Zgłoś znalezisko właścicielowi systemu lub administratorowi; nie używaj go, nie testuj "
              "i nie poszerzaj nim dostępu (zasada 3).",
    },
    "otp_do_not_store": {
        "en": "One-time codes must not be stored, logged, or repeated - use them only for the current "
              "task (policy 7).",
        "pl": "Kodów jednorazowych nie wolno przechowywać, logować ani powtarzać - użyj ich wyłącznie "
              "w bieżącym zadaniu (zasada 7).",
    },
    "verify_ownership": {
        "en": "Ownership is unverified; confirm it with the owner before acting on this finding (policy 6).",
        "pl": "Własność jest niezweryfikowana; potwierdź ją u właściciela, zanim podejmiesz działania "
              "(zasada 6).",
    },
}

VERIFICATION_LABEL = {
    "pattern-match": {"en": "pattern-match (format recognised, not validated)",
                      "pl": "zgodność ze wzorcem (format rozpoznany, bez walidacji)"},
    "unverified": {"en": "unverified (heuristic match)",
                   "pl": "niezweryfikowane (dopasowanie heurystyczne)"},
}


# --------------------------------------------------------------------------- #
# Masking (policies 1, 5, 7)
# --------------------------------------------------------------------------- #


PREFIX_KEEP = 7   # "sk-1234"
SUFFIX_KEEP = 4   # "cdef"


def mask_secret(value: str, mask_char: str = DEFAULT_MASK_CHAR) -> str:
    """Mask a value, keeping at most 7 leading and 4 trailing characters.

    ``sk-1234567890abcdef`` -> ``sk-1234••••••cdef`` (policy 1).
    Short values leak nothing at all - the prefix/suffix is only kept when it
    cannot, by itself, be used to reconstruct or confirm the secret.
    """
    v = value.strip()
    if not v:
        return mask_char * MASK_RUN
    if len(v) <= 8:
        return mask_char * MASK_RUN
    if len(v) <= 14:
        return v[:2] + mask_char * MASK_RUN + v[-2:]
    return v[:PREFIX_KEEP] + mask_char * MASK_RUN + v[-SUFFIX_KEEP:]


def mask_for(rule: Rule, raw: str, mask_char: str = DEFAULT_MASK_CHAR) -> str:
    """Rule-aware masking.

    One-time codes (policy 7) and key blocks (policy 3) get no prefix/suffix at
    all; the PEM header is kept because it is a type label, not key material.
    """
    if rule.category == "otp":
        return mask_char * MASK_RUN
    if rule.id == "private_key_pem":
        return f"{raw} {mask_char * MASK_RUN} REDACTED"
    return mask_secret(raw, mask_char)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    """True when the value is clearly a template, an env reference or filler."""
    v = value.strip().strip("\"'`").strip()
    if not v or len(v) < 4:
        return True
    if TEMPLATE_RE.match(v):
        return True
    if v.startswith(("/", "./", "../", "~", "\\\\", "env:", "config:")):
        return True
    if v.endswith((".env", ".pem", ".key")):
        return True
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", v.lower()) if t]
    if tokens and all(t in PLACEHOLDER_WORDS for t in tokens):
        return True
    if len(tokens) > 1 and len(set(tokens)) == 1:
        return True
    if re.fullmatch(r"(\d)\1+", re.sub(r"\D", "", v) or "x"):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{3,}", v) and "_" in v:  # ENV_VAR reference
        return True
    return False


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    id: str
    type: str
    service: str
    severity: str
    category: str
    path: str
    line: int
    mask: str
    fingerprint: str
    verification: str
    snippet: str
    full_value: Optional[str] = None  # only under an authorised disclosure (policy 2)
    disclosure: str = "masked"
    ownership: str = "unknown"
    remediation: List[str] = field(default_factory=list)

    def to_json(self, lang: str) -> dict:
        data = {
            "id": self.id,
            "type": self.type,
            "service": self.service,
            "severity": self.severity,
            "category": self.category,
            "source": {"path": self.path, "line": self.line},
            "masked_value": self.mask,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
            "verification_status": self.verification,
            "verification_status_text": VERIFICATION_LABEL[self.verification][lang],
            "ownership": self.ownership,
            "disclosure": self.disclosure,
            "remediation": [{"action": k, "text": REMEDIATION[k][lang]} for k in self.remediation],
        }
        if self.disclosure == "full-authorized" and self.full_value is not None:
            data["value"] = self.full_value
        return data


@dataclass
class Span:
    start: int
    end: int
    rule: Rule
    raw: str
    mask: str

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


def iter_candidate_spans(line: str, mask_char: str = DEFAULT_MASK_CHAR) -> List[Span]:
    """Return non-overlapping spans for one line, most specific rule winning."""
    spans: List[Span] = []
    for rule in RULES:
        for m in rule.pattern.finditer(line):
            groups = m.re.groups or 0
            if rule.group and rule.group <= groups and m.group(rule.group) is not None:
                raw = m.group(rule.group)
                start, end = m.span(rule.group)
            else:
                raw = m.group(0)
                start, end = m.span(0)
            if not raw:
                continue
            if rule.generic or rule.priority <= 58:
                if looks_like_placeholder(raw) or CODE_ARTIFACT_RE.search(raw):
                    continue
                if rule.generic and (len(raw) < 12 or shannon_entropy(raw) < 3.0):
                    continue
                if rule.id == "recovery_code_block" and (
                    "-" not in raw or sum(ch.isdigit() for ch in raw) < 2
                ):
                    continue  # hyphen-separated groups with digits, not prose
            spans.append(Span(start, end, rule, raw, mask_for(rule, raw, mask_char)))

    spans.sort(key=lambda s: (-s.rule.priority, s.start))
    kept: List[Span] = []
    for span in spans:
        if any(span.overlaps(k) for k in kept):
            continue
        kept.append(span)
    kept.sort(key=lambda s: s.start)
    return kept


KEY_BODY_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")


def key_material_follows(lines: Sequence[str], header_line: int) -> bool:
    """True when a PEM header is followed by base64 key material or an END marker.

    A header quoted in documentation (no material, no END line) is still worth a
    review, but it is not a leaked key - the severity is lowered accordingly.
    """
    for follow in lines[header_line: header_line + 5]:  # header_line is 0-based here
        stripped = follow.strip()
        if not stripped:
            continue
        if stripped.startswith("-----END") or "-----END" in stripped:
            return True
        return bool(KEY_BODY_RE.match(stripped))
    return False


def redact_line(line: str, spans: Sequence[Span], limit: int = 200) -> str:
    """Rebuild a line with every detected secret replaced by its mask (policy 4)."""
    chunks: List[str] = []
    last = 0
    for span in spans:
        chunks.append(line[last:span.start])
        chunks.append(span.mask)
        last = span.end
    chunks.append(line[last:])
    text = "".join(chunks).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #


class IgnoreRules:
    """gitignore-style matcher backed by ``.secretsignore``."""

    def __init__(self, patterns: Sequence[str], path: Optional[str] = None):
        self.patterns = [p for p in (pat.strip() for pat in patterns) if p and not p.startswith("#")]
        self.path = path

    @classmethod
    def load(cls, path: Optional[str]) -> "IgnoreRules":
        if not path or not os.path.isfile(path):
            return cls(())
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return cls(fh.readlines(), path=os.path.abspath(path))

    def matches(self, rel_path: str) -> bool:
        rel = rel_path.replace(os.sep, "/")
        decision = False
        for pattern in self.patterns:
            negate = pattern.startswith("!")
            pat = pattern[1:] if negate else pattern
            anchor = pat.startswith("/")
            pat = pat.lstrip("/")
            if anchor:
                hit = fnmatch.fnmatch(rel, pat) or rel == pat
            else:
                hit = (
                    fnmatch.fnmatch(rel, pat)
                    or fnmatch.fnmatch(rel, f"*/{pat}")
                    or fnmatch.fnmatch(os.path.basename(rel), pat)
                )
            if hit:
                decision = not negate
        return decision


class IgnoreChain:
    """Composite of every ``.secretsignore`` that applies to the scanned paths."""

    def __init__(self, rules: Sequence[IgnoreRules]):
        self.rules = list(rules)

    @classmethod
    def load(cls, candidates: Sequence[str]) -> "IgnoreChain":
        seen = set()
        rules = []
        for candidate in candidates:
            if not candidate:
                continue
            real = os.path.abspath(candidate)
            if real in seen:
                continue
            seen.add(real)
            if os.path.isfile(real):
                rules.append(IgnoreRules.load(real))
        return cls(rules)

    def matches(self, rel_path: str) -> bool:
        return any(rule.matches(rel_path) for rule in self.rules)

    @property
    def paths(self) -> List[str]:
        return [rule.path for rule in self.rules if getattr(rule, "path", None)]


def ignore_candidates(args: argparse.Namespace, root: str) -> List[str]:
    """Ignore files that apply to a scan.

    An explicit ``--ignore-file`` is authoritative; otherwise the default
    ``.secretsignore`` is picked up from the git root and from every directory
    that is scanned, so subprojects can carry their own rules.
    """
    if args.ignore_file != DEFAULT_IGNORE_FILE:
        path = args.ignore_file
        return [path if os.path.isabs(path) else os.path.join(root, path)]

    candidates: List[str] = []
    if args.root:
        candidates.append(os.path.join(root, DEFAULT_IGNORE_FILE))
    else:
        git_root = _git_root(os.getcwd())
        if git_root:
            candidates.append(os.path.join(git_root, DEFAULT_IGNORE_FILE))
    for path in args.paths:
        if os.path.isdir(path):
            candidates.append(os.path.join(os.path.abspath(path), DEFAULT_IGNORE_FILE))
    return candidates


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _relpath(path: str, root: str) -> str:
    """Display path relative to the root, or absolute when outside the root."""
    absolute = os.path.abspath(path)
    try:
        rel = os.path.relpath(absolute, root)
    except ValueError:  # different drive on Windows
        return absolute.replace(os.sep, "/")
    if rel.startswith(".." + os.sep) or rel == "..":
        return absolute.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


def _git_root(start: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def staged_sources(root: str) -> List[Tuple[str, bytes]]:
    """Return staged (index) content, so a pre-commit hook scans what is committed."""
    try:
        listing = subprocess.run(
            ["git", "-C", root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
            capture_output=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: cannot list staged files: {exc}")
    if listing.returncode != 0:
        raise SystemExit("error: --git-staged must run inside a git working tree")
    names = [n for n in listing.stdout.decode("utf-8", "replace").split("\0") if n]
    sources: List[Tuple[str, bytes]] = []
    for name in names:
        blob = subprocess.run(["git", "-C", root, "show", f":{name}"], capture_output=True, timeout=20)
        if blob.returncode == 0:
            sources.append((name, blob.stdout))
    return sources


def collect_sources(
    paths: Sequence[str],
    root: str,
    ignores: IgnoreChain,
    max_bytes: int,
) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """Return (sources, skipped) where sources are (display_path, content)."""
    sources: List[Tuple[str, bytes]] = []
    skipped: List[str] = []

    def add_file(fs_path: str, display: str) -> None:
        if ignores.matches(display):
            skipped.append(f"{display} (ignored)")
            return
        if os.path.splitext(display)[1].lower() in SKIP_SUFFIXES:
            skipped.append(f"{display} (binary extension)")
            return
        try:
            size = os.path.getsize(fs_path)
        except OSError as exc:
            skipped.append(f"{display} ({exc})")
            return
        if size > max_bytes:
            skipped.append(f"{display} (larger than {max_bytes} bytes)")
            return
        with open(fs_path, "rb") as fh:
            data = fh.read()
        if _is_binary(data):
            skipped.append(f"{display} (binary)")
            return
        sources.append((display, data))

    for path in paths:
        if not os.path.exists(path):
            skipped.append(f"{path} (does not exist)")
            continue
        if os.path.isfile(path):
            add_file(path, _relpath(path, root))
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d != ".git")
            for name in sorted(filenames):
                fs_path = os.path.join(dirpath, name)
                add_file(fs_path, _relpath(fs_path, root))
    return sources, skipped


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


def scan_text(
    text: str,
    display_path: str,
    ownership: str = "unknown",
    mask_char: str = DEFAULT_MASK_CHAR,
) -> List[Finding]:
    """Scan one text blob and return masked findings (policies 1, 4, 5, 6)."""
    findings: List[Finding] = []
    if INLINE_IGNORE_FILE_RE.search(text):
        return findings

    lines = text.splitlines()
    skip_next = False
    for number, line in enumerate(lines, start=1):
        if skip_next:
            skip_next = False
            continue
        if INLINE_IGNORE_LINE_RE.search(line):
            continue
        if INLINE_IGNORE_NEXT_RE.search(line):
            skip_next = True
            continue

        spans = iter_candidate_spans(line, mask_char)
        if not spans:
            continue
        snippet = redact_line(line, spans)
        for span in spans:
            severity = span.rule.severity
            if span.rule.id == "private_key_pem" and not key_material_follows(lines, number):
                severity = "medium"  # a quoted header is not key material
            fingerprint = hashlib.sha256(
                f"{display_path}|{span.rule.id}|{span.mask}".encode("utf-8")
            ).hexdigest()[:16]
            finding = Finding(
                id="",
                type=span.rule.id,
                service=span.rule.service,
                severity=severity,
                category=span.rule.category,
                path=display_path,
                line=number,
                mask=span.mask,
                fingerprint=fingerprint,
                verification="pattern-match" if span.rule.priority > 58 else "unverified",
                snippet=snippet,
                ownership=ownership,
            )
            if ownership == "third_party":
                # policy 3: never use, never test, never expand access
                finding.remediation = ["report_to_owner", "remove_from_source", "revoke_or_rotate"]
            elif span.rule.category == "otp":
                # policy 7: do not store or repeat one-time codes
                finding.remediation = ["otp_do_not_store", "remove_from_source"]
            else:
                finding.remediation = ["revoke_or_rotate", "remove_from_source", "purge_from_history"]
            if ownership == "unknown":
                finding.remediation.append("verify_ownership")
            findings.append(finding)
    return findings


def scan_sources(
    sources: Sequence[Tuple[str, bytes]],
    ownership: str = "unknown",
    reveal: bool = False,
    declared_files: Sequence[str] = (),
    mask_char: str = DEFAULT_MASK_CHAR,
) -> List[Finding]:
    findings: List[Finding] = []
    declared = {os.path.abspath(p) for p in declared_files}
    for display, data in sources:
        text = data.decode("utf-8", "replace")
        found = scan_text(text, display, ownership, mask_char)
        if reveal and not display.startswith("<") and os.path.abspath(display) in declared:
            lines = text.splitlines()
            for finding in found:
                if not (1 <= finding.line <= len(lines)):
                    continue
                for span in iter_candidate_spans(lines[finding.line - 1], mask_char):
                    if span.rule.id == finding.type and span.mask == finding.mask:
                        finding.disclosure = "full-authorized"
                        finding.full_value = span.raw
                        break
        findings.extend(found)
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.path, f.line))
    for index, finding in enumerate(findings, start=1):
        finding.id = f"F-{index:04d}"
    return findings


# --------------------------------------------------------------------------- #
# Reports (policies 4 + 5: masked values only, no secrets in metadata)
# --------------------------------------------------------------------------- #


def build_report(
    findings: Sequence[Finding],
    sources: Sequence[Tuple[str, bytes]],
    skipped: Sequence[str],
    args: argparse.Namespace,
    root: str,
    ignore_files: Sequence[str] = (),
) -> dict:
    counts = Counter(f.severity for f in findings)
    report = {
        "schema": SCHEMA,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "tool": {"name": "mask_secrets", "version": VERSION, "network_used": False},
        "policy": {"documents": [POLICY_PL, POLICY_EN], "clauses": ["1", "3", "4", "5", "6", "7", "8"]},
        "scan": {
            "root": root,
            "scope": list(args.paths) or ([("<stdin>")] if args.stdin else ["<git-staged>"]),
            "ownership": args.ownership,
            "files_scanned": len(sources),
            "files_skipped": len(skipped),
            "skipped": list(skipped),
            "ignore_files": [
                os.path.relpath(p, root) if os.path.isabs(p) and p.startswith(root + os.sep) else p
                for p in ignore_files
            ],
        },
        "summary": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "total": len(findings),
        },
        "findings": [f.to_json(args.lang) for f in findings],
    }
    if args.reveal:
        report["authorization"] = {
            "reveal_requested": True,
            "statement": args.confirm_ownership,
            "declared_files": list(args.owned_file),
        }
    return report


def render_text(report: dict, findings: Sequence[Finding], args: argparse.Namespace) -> str:
    msg = MESSAGES[args.lang]
    lines: List[str] = []
    lines.append(f"=== {msg['title']} ===")
    lines.append(
        f"{msg['generated']}: {report['generated_at']} | {msg['tool']}: mask_secrets "
        f"v{VERSION} | {msg['network']}: {msg['no_network_value']}"
    )
    lines.append(
        f"{msg['policy']}: {POLICY_PL} / {POLICY_EN} | {msg['ownership']}: "
        f"{OWNERSHIP_LABEL[args.ownership][args.lang]} | {msg['scope']}: {', '.join(report['scan']['scope'])}"
    )
    lines.append(
        f"{msg['files_scanned']}: {report['scan']['files_scanned']} | "
        f"{msg['files_skipped']}: {report['scan']['files_skipped']} | "
        f"{msg['findings']}: {report['summary']['total']}"
    )
    lines.append("")
    if not findings:
        lines.append(msg["no_findings"])
    for finding in findings:
        lines.append(f"[{finding.severity.upper()}] {finding.id} {finding.type} ({finding.service})")
        lines.append(f"  {msg['source']}: {finding.path}:{finding.line}")
        if finding.disclosure == "full-authorized" and finding.full_value is not None:
            lines.append(f"  {msg['value']}: {finding.full_value}   <- {msg['reveal_scope']}")
        else:
            lines.append(f"  {msg['value']}: {finding.mask}")
        lines.append(f"  {msg['status']}: {VERIFICATION_LABEL[finding.verification][args.lang]}")
        lines.append(f"  {msg['context']}: {finding.snippet}")
        for action in finding.remediation:
            lines.append(f"  - {msg['advice']}: {REMEDIATION[action][args.lang]}")
        lines.append("")
    lines.append(
        f"{msg['summary']}: critical={report['summary']['critical']} high={report['summary']['high']} "
        f"medium={report['summary']['medium']} {msg['total']}={report['summary']['total']}"
    )
    if any(f.ownership == "third_party" for f in findings):
        lines.append(msg["third_party_notice"])
    if args.ownership == "unknown" and findings:
        lines.append(msg["unverified_notice"])
    lines.append(msg["footer"])
    return "\n".join(lines) + "\n"


def render_markdown(report: dict, findings: Sequence[Finding], args: argparse.Namespace) -> str:
    msg = MESSAGES[args.lang]
    out = [f"# {msg['title']}", ""]
    out.append(
        f"- {msg['generated']}: `{report['generated_at']}`\n"
        f"- {msg['tool']}: `mask_secrets v{VERSION}` ({msg['network']}: {msg['no_network_value']})\n"
        f"- {msg['policy']}: `{POLICY_PL}` / `{POLICY_EN}`\n"
        f"- {msg['ownership']}: {OWNERSHIP_LABEL[args.ownership][args.lang]}\n"
        f"- {msg['scope']}: `{', '.join(report['scan']['scope'])}`"
    )
    out.append("")
    out.append(
        f"**{msg['summary']}:** critical={report['summary']['critical']} "
        f"high={report['summary']['high']} medium={report['summary']['medium']} "
        f"{msg['total']}={report['summary']['total']}"
    )
    out.append("")
    if not findings:
        out.append(msg["no_findings"])
    else:
        out.append(f"| ID | {msg['findings']} | {msg['source']} | {msg['value']} | {msg['status']} |")
        out.append("| --- | --- | --- | --- | --- |")
        for finding in findings:
            value = finding.mask if finding.disclosure != "full-authorized" else "[shown on stdout]"
            out.append(
                f"| {finding.id} | {finding.severity.upper()} `{finding.type}` ({finding.service}) | "
                f"`{finding.path}:{finding.line}` | `{value}` | {finding.verification} |"
            )
    out.append("")
    if any(f.ownership == "third_party" for f in findings):
        out.append(f"> {msg['third_party_notice']}")
        out.append("")
    out.append(msg["footer"])
    return "\n".join(out) + "\n"


def render_sarif(report: dict, findings: Sequence[Finding]) -> str:
    used_rules = []
    seen = set()
    for finding in findings:
        if finding.type in seen:
            continue
        seen.add(finding.type)
        used_rules.append(
            {
                "id": finding.type,
                "name": finding.type.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": finding.service},
                "defaultConfiguration": {
                    "level": "error" if finding.severity in ("critical", "high") else "warning"
                },
                "properties": {"tags": ["security", "secrets", "policy"], "severity": finding.severity},
            }
        )
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.type,
                "level": "error" if finding.severity in ("critical", "high") else "warning",
                "message": {
                    "text": f"Potential secret ({finding.service}) at {finding.path}:{finding.line}. "
                            f"Masked value: {finding.mask}. Verification: {finding.verification}."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "partialFingerprints": {"alhSecretFingerprint": finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "category": finding.category,
                    "verificationStatus": finding.verification,
                    "ownership": finding.ownership,
                    "disclosure": finding.disclosure,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ALHacking mask_secrets",
                        "version": VERSION,
                        "informationUri": "https://github.com/ALIEN-luk/ALHacking",
                        "rules": used_rules,
                    }
                },
                "results": results,
                "properties": {
                    "policyDocuments": [POLICY_PL, POLICY_EN],
                    "maskedOnly": True,
                    "networkUsed": False,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mask_secrets",
        description="Scan text for secrets and report them masked by default "
                    "(see SECRETS_POLICY.md / SECRETS_POLICY.en.md).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  mask_secrets.py .                      # scan the repository, masked report\n"
               "  mask_secrets.py --git-staged --fail-on high\n"
               "  mask_secrets.py --format markdown --out SECRETS_REPORT.md .\n"
               "  mask_secrets.py --format sarif --out secrets.sarif .\n"
               "  mask_secrets.py env/app.env --reveal --ownership user \\\n"
               "      --owned-file env/app.env --confirm-ownership 'I own this file'\n"
               "\n"
               "The tool never makes network requests and never validates a credential.\n",
    )
    parser.add_argument("paths", nargs="*", default=[], help="files or directories to scan")
    parser.add_argument("--version", action="version", version=f"mask_secrets {VERSION}")
    parser.add_argument("--list-rules", action="store_true", help="print the detection rules and exit")
    parser.add_argument("--stdin", action="store_true", help="read the material from standard input")
    parser.add_argument("--git-staged", action="store_true", help="scan the content staged in the git index")
    parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    parser.add_argument("--out", help="write the report to this file (masked output only)")
    parser.add_argument("--lang", choices=("en", "pl"), default=os.environ.get("ALH_SECRETS_LANG", "en"))
    parser.add_argument("--ownership", choices=("unknown", "user", "third_party"), default="unknown")
    parser.add_argument("--reveal", action="store_true",
                        help="print full values for declared owned files (policy 2)")
    parser.add_argument("--owned-file", action="append", default=[],
                        help="declare ownership of a file (repeatable)")
    parser.add_argument("--confirm-ownership", help="explicit ownership statement recorded in the report")
    parser.add_argument("--ignore-file", default=DEFAULT_IGNORE_FILE,
                        help="ignore file (default: .secretsignore)")
    parser.add_argument("--no-ignore-file", action="store_true", help="do not honour the ignore file")
    parser.add_argument("--fail-on", choices=("none", "medium", "high", "critical"), default="high")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_BYTES,
                        help="skip files larger than this")
    parser.add_argument("--mask-char", default=DEFAULT_MASK_CHAR, help="character used for masking")
    parser.add_argument("--root", help="path used to resolve relative locations and the ignore file")
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    msg = MESSAGES[args.lang]

    def die(text: str) -> None:
        parser.error(text)

    if args.reveal:
        if args.ownership == "third_party":
            die(msg["reveal_denied_third_party"])
        if args.ownership != "user" or not args.confirm_ownership or not args.owned_file:
            die(msg["reveal_denied_authorization"])
        if args.format != "text" or args.out:
            die(msg["reveal_denied_format"])
    if args.ownership == "user" and not args.confirm_ownership:
        die("--ownership user requires --confirm-ownership '<statement>' (policy 2).")
    if len(args.mask_char) != 1:
        die("--mask-char must be exactly one character")
    if not args.paths and not args.stdin and not args.git_staged:
        args.paths = ["."]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)

    if args.list_rules:
        for rule in RULES:
            print(f"{rule.id:28s} {rule.severity:8s} {rule.service:24s} {rule.description}")
        return 0

    root = os.path.abspath(args.root) if args.root else (_git_root(os.getcwd()) or os.getcwd())
    ignores = IgnoreChain(()) if args.no_ignore_file else IgnoreChain.load(
        ignore_candidates(args, root)
    )

    if args.reveal:
        print(MESSAGES[args.lang]["reveal_warning"], file=sys.stderr)

    sources: List[Tuple[str, bytes]] = []
    skipped: List[str] = []
    if args.stdin:
        sources.append(("<stdin>", sys.stdin.buffer.read()))
    if args.git_staged:
        staged = staged_sources(root)
        # ignore rules apply to the index exactly as they do to the working tree
        sources.extend(item for item in staged if not ignores.matches(item[0]))
        skipped.extend(
            f"{item[0]} (ignored)" for item in staged if ignores.matches(item[0])
        )
    if args.paths:
        collected, skipped = collect_sources(args.paths, root, ignores, args.max_file_size)
        sources.extend(collected)

    if not sources and not skipped:
        print(MESSAGES[args.lang]["nothing_to_scan"], file=sys.stderr)
        return 0

    findings = scan_sources(sources, args.ownership, args.reveal, args.owned_file, args.mask_char)
    report = build_report(findings, sources, skipped, args, root, [r.path for r in ignores.rules])

    if args.format == "json":
        payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    elif args.format == "markdown":
        payload = render_markdown(report, findings, args)
    elif args.format == "sarif":
        payload = render_sarif(report, findings)
    else:
        payload = render_text(report, findings, args)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"report written to {args.out} (masked values only)", file=sys.stderr)
    else:
        sys.stdout.write(payload)

    threshold = {"none": 99, "medium": 1, "high": 2, "critical": 3}[args.fail_on]
    worst = max((SEVERITY_RANK.get(f.severity, 0) for f in findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
