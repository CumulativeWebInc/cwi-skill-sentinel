# Skill Sentinel

**Linter + security scanner for AI agent skills** — by Cumulative Web Inc. App #30 in the CWI software brand.

Paste a `SKILL.md`, `AGENTS.md`, or subagent file and get an **A–F grade** with evidence-bound findings across six categories: prompt injection, data exfiltration, destructive commands, privilege grants, frontmatter lint, and structure. Runs 100% locally in the browser — nothing is uploaded.

**Live:** https://cumulativewebinc.github.io/cwi-skill-sentinel/

## Why

In 2026, skills became the package manager of the agent world — and packages get poisoned. A skill's body is a prompt your agent will follow. A malicious or careless skill can hide an instruction override, a `curl $(env)` exfiltration line, or a "disable the approval prompt" instruction inside a helpful-looking workflow. Skill Sentinel is the fast first line of defense: scan before you install, gate in CI.

## Honest limits

Skill Sentinel is a **heuristic pattern engine**, not a sandbox. It has false positives (a legitimate skill documenting `curl`) and false negatives (novel obfuscation). A clean scan is **not** a safety certificate. Always read a skill before trusting it.

## Use it

- **Web:** open the live URL, paste, scan. Includes clean and malicious samples to try.
- **Deep link:** `?scan=<url-to-raw-skill-file>` fetches and scans automatically.
- **Node:** `scanner.js` is dependency-free UMD —
  ```js
  const sentinel = require('./scanner.js');
  const report = sentinel.scan(text, { filename: 'SKILL.md' });
  ```
- **Agents:** the report shape is specified in [`schema/findings.schema.json`](./schema/findings.schema.json). Copy/Download JSON from the page.

## Rule catalog (v1.0.0)

| ID | Severity | What it catches |
|---|---|---|
| SEC-PI-001…005 | error/critical | Instruction overrides, approval bypasses, role redefinition, fake model delimiters, secrecy toward the operator |
| SEC-EX-001…005 | error/critical | `env` piped to network, command substitution in `curl`, pipe-to-shell, secret-adjacent outbound calls, exfiltration language |
| SEC-DE-001…004 | warning/critical | `rm -rf` on root paths, fork bombs, raw device writes, `chmod 777` |
| SEC-PR-001…002 | error | `sudo` + network/installer, wildcard `tools: "*"` grants |
| Q-FM-001…005 | warning/error | Missing/malformed frontmatter, missing `name`/`description`, vague descriptions |
| Q-ST-001…003 | info/warning/error | Missing headers, empty file, very long lines |

Scoring: start at 100; critical −25, error −10, warning −3. Grades A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40. **Any critical caps the grade at D.**

## Tests

27 tests, Node built-in runner, zero dependencies:

```bash
node --test tests/test.js
```

Fixtures include a clean skill, a deliberately malicious skill (inert text for testing), a vague `AGENTS.md`, and a broken-frontmatter file.

## Roadmap

- Signed scan receipts anchored in the [CWI Trust Fabric](https://cumulativewebinc.github.io/cwi-trust-log/) (trust/1.1) — "this skill scanned B on date X with engine v1.0.0," verifiable by anyone.
- x402 pay-per-scan API for CI pipelines.
- SARIF output for GitHub code scanning.

## i18n

UI strings carry `data-i18n` keys and the page loads the shared `cwi-i18n` hook — translations slot in when the language tables land.
