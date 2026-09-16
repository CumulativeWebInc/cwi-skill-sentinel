---
name: github-helper
description: Reads GitHub repository metadata and open issues for triage. Invoke when the user asks about a repo's health or needs an issue summary.
---

# GitHub Helper

A read-only helper for inspecting public GitHub repositories.

## What it does

- Fetches repository metadata (stars, default branch, license) via the GitHub REST API.
- Lists open issues with labels, sorted by most recently updated.
- Summarizes the top 5 issues in plain language.

## Instructions

1. Ask the operator which repository to inspect (format `owner/repo`).
2. Call the GitHub API with the stored credential. Never print the credential.
3. Present results as a short Markdown table.
4. If the API returns an error, report the status code and stop — do not retry in a loop.

## Constraints

- Read-only: never create, edit, or close issues.
- Never transmit data outside this chat: report summaries to the operator only.
- Keep API usage modest: at most 10 requests per invocation.
