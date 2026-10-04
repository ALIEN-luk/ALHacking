#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test fixtures for mask_secrets.py.

Every value below is deliberately invalid: the literal filler ``EXAMPLE`` is
never a real credential.  They still have to *look* like the real formats,
which is exactly why this single file is listed in ``.secretsignore`` (the
policy document explains the allowlist).  Keep credentials of any real system
out of this file - and out of the repository in general.
"""

# OpenAI / Anthropic style
SAMPLE_OPENAI = "sk-proj-EXAMPLEexample1EXAMPLEEXAMPLEEXA"
SAMPLE_ANTHROPIC = "sk-ant-api03-" + "EXAMPLEexample2" + "EXAMPLE" * 4

# Cloud
SAMPLE_AWS_ID = "AKIAEXAMPLEEXAMPLEEX"
SAMPLE_AWS_SECRET = "ExampleEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMP"
SAMPLE_GOOGLE = "AIzaEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"

# Code hosting, messaging, payments
SAMPLE_GITHUB = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE"
SAMPLE_GITLAB = "glpat-EXAMPLEEXAMPLEEXAMPL"
SAMPLE_HF = "hf_" + "E" * 34
SAMPLE_SLACK = "xoxb-EXAMPLEEXAMPLEEXAMPLEEXA"
SAMPLE_STRIPE = "sk_live_" + "EXAMPLE" * 4

# Generic credentials
SAMPLE_JWT = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
    ".eyJzdWIiOiAiRVhBTVBMRSIsICJleHAiOiAxODkzNDU2MDAwfQ"
    ".RVhBTVBMRXNpZ25hdHVyZUVYQU1QTEUxMjM0"
)
SAMPLE_DB_URI = "postgres://appuser:EXAMPLEdbpassword123@db.internal:5432/app"
SAMPLE_PASSWORD = "S3cr3t-EXAMPLE-Value123"
SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----"
# A base64 body used only to prove that a "real" block is rated critical.
SAMPLE_KEY_BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt"
SAMPLE_OTP = "backup codes: 4821-9374-1052"
SAMPLE_RECOVERY_BLOCK = "recovery codes: 4c1f-8a2b-9d7e-3f60"
SAMPLE_LICENSE = "LICENSE_KEY=EXAMPLE-LIC-1234-5678-9012"

# One-time codes in the shapes they appear in real files (policy 7)
OTP_LINES = (
    "2FA_BACKUP_CODES=4821-9374-1052",
    SAMPLE_RECOVERY_BLOCK,
    "your recovery codes are 5a1b-9c2d-7e3f",
    "otp: 90210",
    "verification code: 1234",
)

# Values that only look like secrets and must never be reported
PLACEHOLDER_LINES = (
    'api_key = "your_api_key_here"',
    "password = ${DB_PASSWORD}",
    "token: <TOKEN>",
    "secret = CHANGE_ME",
    'password = "xxxxxxxx"',
    "api_key: process.env.API_KEY",
    "backup codes: xxxx-xxxx-xxxx",
)
