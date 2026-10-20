# Changelog

## 0.1.0 (unreleased)

- First release.
- Scans agent folders (Claude Code, Codex CLI, Gemini CLI, OpenCode, Continue, Cline), agent and MCP configs, editor storage (VS Code, Cursor, Windsurf and forks), shell history and startup files, and the project directory.
- Recognises Anthropic API keys and Claude login tokens, OpenAI and OpenAI-compatible, Google, OpenRouter, Groq, xAI, Hugging Face, Perplexity, Replicate, GitHub and AWS keys, including right after JSON escapes and URL encoding.
- Reads UTF-8, UTF-16 and binary files (such as SQLite databases), and large files in chunks.
- Anything that could not be scanned is reported and marks the scan as partial (exit code 3).
- Judges `.env` risk with `.gitignore`, `.git/info/exclude` and the global git excludes file.
- Does not walk the home or root folder as a project unless asked with `--path`; `--path` accepts a single file.
- `.keyleakcheckignore` and `--ignore <id>` for known test keys.
- Masked text, JSON and score card output; control and bidi characters in file names are neutralised.
- Low-risk classification, with a plain explanation, for credential stores, embedded browser caches and expired temporary AWS keys; repeated hits are grouped per file.
- Revoke and spend-limit guidance per provider.
- Offline, read-only, zero dependencies; every promise is enforced by static, behaviour, randomised and runtime tests.
