# Key Leak Check

**Find the API keys your AI agents left in plaintext. In 60 seconds, offline.**

Coding agents and MCP clients write what you paste into them to plaintext files on disk: chat transcripts, MCP configs, settings. Shell history keeps every `export OPENAI_API_KEY=...` you ever typed. Repo scanners don't look there, because these files are not in a repo.

Key Leak Check scans those places for AI provider keys, shows them masked, and tells you how to revoke each one and cap spend on its replacement.

```sh
npx keyleakcheck
```

Requires Node.js 20 or newer. No install, no account, no network.

Run it from a project folder to also scan that project. Run from your home folder, it checks agent, MCP and shell files only and does not walk everything you own.

## What it checks

| Where | Examples | Risk |
| --- | --- | --- |
| Agent folders: chat history, logs, settings, shell snapshots | Claude Code `~/.claude` (or `$CLAUDE_CONFIG_DIR`), Codex CLI `~/.codex` (or `$CODEX_HOME`), Gemini CLI `~/.gemini`, GitHub Copilot CLI `~/.copilot`, OpenCode, Continue, Cline CLI | High |
| Agent and MCP configs | `~/.claude.json`, Claude Desktop `claude_desktop_config.json`, Cursor `~/.cursor/mcp.json`, Windsurf `mcp_config.json`, Aider, project `.mcp.json` | High |
| Editor storage | Cline and Roo Code task history, and `state.vscdb` chat databases, for VS Code, VS Code Insiders, VSCodium, Cursor, Windsurf and Antigravity | High |
| Shell history | bash, zsh, fish, PowerShell | High |
| Shell startup files | `.zshrc`, `.bashrc`, `.profile`, `config.fish`, PowerShell profiles | Medium |
| Credential stores | `~/.claude/.credentials.json`, `~/.codex/auth.json`, OpenCode `auth.json`, the `primaryApiKey` field in `~/.claude.json` | Low: expected place, reported for awareness |
| Browser caches inside agent folders | For example Antigravity's browser profile in `~/.gemini`. Keys there usually belong to websites you visited (Google API keys are public by design) | Low, unless the same key also appears elsewhere |
| Temporary AWS credentials (`ASIA…`) | Anywhere | High while they can still work; low once the file is older than their 36-hour maximum lifetime |
| Your project | Source, config and log files in about 80 formats; `.env` and `.envrc` (medium if gitignored, high if not); `.env.example` (high: usually committed); build output such as `dist` and `.next` (a key there may ship to users). Skips `node_modules`, `.git` and Python virtual environments | High |

Text in UTF-8, UTF-16 (the Windows PowerShell 5.1 default) and binary files such as SQLite databases is scanned; for binary files the report shows how often a key occurs instead of meaningless line numbers. Keys are found right after JSON escapes (`\n`, `"`) and URL encoding (`%22`), which is how they appear in agent transcripts and logs.

Run `npx keyleakcheck --list-locations` to see the exact paths on your machine. Agent file locations change between versions; if one is missing, [open an issue](.github/ISSUE_TEMPLATE/missing-location.yml).

Keys it recognises: Anthropic API keys and Claude login tokens, OpenAI (and OpenAI-compatible `sk-` keys such as DeepSeek), Google Gemini/Cloud, OpenRouter, Groq, xAI, Hugging Face, Perplexity, Replicate, GitHub and AWS access keys.

Keys it **cannot** recognise, because they have no fixed prefix: Mistral, Cohere, Together AI, Azure OpenAI and other plain random strings. Check those by hand.

## Example output

Illustrative; your numbers and paths will differ.

```text
Key Leak Check 0.1.0  (offline, read-only)

Scanned 412 files across 7 locations.
Found 2 exposed key(s) in 3 place(s). Grade: C

1. Anthropic  sk-ant-api03-…F5AA  HIGH  id b2973d6dbc00
   ~/.claude/projects/my-app/session.jsonl:214  agent chat history, Claude Code
   ~/.zsh_history:1093  shell history, zsh
   Fix: 1) revoke and replace: https://console.anthropic.com/settings/keys
        2) remove the old key from the files above (or run your agent's history cleanup)
        3) cap spend on the new key: https://console.anthropic.com/settings/limits
```

`--card` prints a shareable summary with no keys and no file paths. `--json` prints machine-readable results with masked keys.

If any file could not be scanned (too large, permission denied) or the file limit was reached, the report says so, lists the files and marks the grade as **partial scan**. A partial scan is never reported as clean.

## Use in CI and pre-commit hooks

Use `--no-home` so the check covers only the repository, not old chat histories on the machine:

```sh
npx keyleakcheck --no-home
```

| Exit code | Meaning |
| --- | --- |
| 0 | No high-risk keys found |
| 1 | High-risk keys found |
| 2 | Error (for example an unknown option) |
| 3 | No high-risk keys found, but some files could not be scanned |

Keeping a fake key on purpose, for example in test fixtures? Add its id (shown in the report as `id 1a2b3c4d5e6f`) to a `.keyleakcheckignore` file in the project root, one per line, or pass `--ignore <id>`. Ids are one-way hashes, so the file is safe to commit.

## Trust: what this tool does and does not do

You are running a program that reads files containing secrets. You should know exactly what it does.

| | |
| --- | --- |
| **Reads** | Only the locations listed by `--list-locations`, the project directory you choose, and the git ignore files that decide whether a `.env` is ignored (`.gitignore`, `.git/info/exclude`, your global git excludes file) plus `.keyleakcheckignore`. Large files are read in 16 MB chunks. Symlinked directories inside a scanned folder are never followed; symlinked files, and a known agent folder that is itself a symlink (common with dotfile managers), are read. |
| **Writes** | Nothing. It never creates, changes or deletes a file. |
| **Sends** | Nothing. It makes no network connections. There is no telemetry, no update check, no licence check. |
| **Prints** | Keys only in masked form: the provider's fixed prefix and the last 4 characters (`sk-proj-…a9F2`), as provider consoles do. Never the full key, never other random characters. |
| **Depends on** | Nothing. Zero runtime dependencies and no install scripts. Only Node.js built-ins `fs`, `path`, `os` and `crypto` are used. |

These are not just promises. They are checked three ways on every commit:

- **Static tests** (`test/guarantees.test.js`) fail if shipped code imports a network or process-spawning module, calls a filesystem write API, opens a file in any mode other than read-only, uses `fetch` or `eval`, or adds a dependency or install script.
- **Behaviour tests** check that no full key appears in any output format, that no file changes during a scan, and every other promise in this README ([full list](VERIFY.md#every-promise-and-the-test-that-checks-it)).
- **A randomised test** (`test/fuzz.test.js`) plants keys of 16 formats at random positions, with random separators, line endings, encodings, line lengths and read sizes, and fails unless every key is found exactly once on the right line.
- **Runtime checks in CI** run a real scan under the Node.js permission model with read-only filesystem access, and under `strace`, failing the build if a single network or file-write system call happens.

At startup the CLI also replaces `fetch` with a function that throws, as a last line of defence. You can reproduce every check yourself: see [VERIFY.md](VERIFY.md).

The whole tool is about 1,000 lines, many of them comments and the list of locations. You can read it in about 30 minutes: start with [`src/scan.js`](src/scan.js).

### Verify what you install

Releases are built and published only by GitHub Actions, never from a laptop.

```sh
# npm provenance: the package was built from this repo's public workflow
npm audit signatures

# GitHub artifact attestation for the release tarball
gh attestation verify keyleakcheck-<version>.tgz --repo synthmodulelab/keyleakcheck

# Checksum published with every GitHub release
sha256sum -c SHA256SUMS
```

Beware of look-alike package names. The only official package is `keyleakcheck`.

## Limitations

- A clean result is not a guarantee. Detection is pattern-based; keys with no recognisable prefix are not found, and neither are keys that were encoded (for example base64) or split across lines.
- Inside databases, a very long value can be split across storage pages; a key that straddles a page boundary is not found.
- It does not check whether a key still works, and it does not edit your files. Both would break the guarantees above. Treat every finding as live until you revoke it, and remove old keys yourself.
- It looks at this machine only. Keys already pushed to a remote, a backup or a cloud sync folder need to be revoked there too.

## Optional companion: keyleakcheck-fix

Checking whether a key is still live needs the network, and redacting keys from history files needs to write to disk. Those features live in a separate, paid package, `keyleakcheck-fix`, that you install only if you want them. It has its own published guarantees: it connects only to a fixed allowlist of official provider API hosts, asks before every request and every file change, and backs up every file before changing it.

This package, `keyleakcheck`, never depends on it and never gains those capabilities.

## Options

```text
--path <dir>        Project directory to scan (default: current directory;
                    skipped automatically if that is your home or root folder)
--no-project        Skip the project directory
--no-home           Skip agent, MCP and shell files in your home directory
                    (recommended for CI and pre-commit hooks)
--ignore <id>       Ignore a finding by its id (repeatable)
--json              Machine-readable output (keys masked)
--card              Shareable score card (no keys, no paths)
--list-locations    Show which locations are checked, without reading them
--max-file-mb <n>   Skip files larger than n MB (default: 2048); skipped files are reported
```

## Security

Found a vulnerability? Please report it privately; see [SECURITY.md](SECURITY.md).

Version 0.1.0 has not yet had an independent security review. The code is small and every guarantee is tested in CI, but a second pair of eyes is welcome: reviews and issues are appreciated.

## License

[MIT](LICENSE)
