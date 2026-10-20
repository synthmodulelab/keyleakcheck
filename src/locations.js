'use strict';

const os = require('os');
const path = require('path');

// Where AI agents, MCP clients, editors and shells are known to keep plaintext
// data. Paths are best-effort: tools move their files between versions.
// Missing paths are skipped and listed by --list-locations so users can see
// coverage.
//
// Order matters: when a file is reachable through two entries, the first one
// wins, so specific files (credential stores) come before folder walks.
//
// kind:
//   credential-store files whose job is to hold a key (expected, low risk)
//   agent-config     agent settings / MCP config (high)
//   agent-data       agent folders: chat history, logs, snapshots (high)
//   editor-data      editor extension storage, incl. databases (high)
//   shell-history    shell command history (high)
//   shell-config     shell startup files such as .zshrc (medium)
//   env              .env files (medium; high if not gitignored)
//
// expectedFields: JSON fields where a key is stored on purpose; a key found
// as the value of one of these fields is treated as a credential store.

function appSupport(home, platform, env) {
  if (platform === 'darwin') return path.join(home, 'Library', 'Application Support');
  if (platform === 'win32') return env.APPDATA || path.join(home, 'AppData', 'Roaming');
  return env.XDG_CONFIG_HOME || path.join(home, '.config');
}

function homeLocations(home = os.homedir(), platform = process.platform, env = process.env) {
  const h = (...p) => path.join(home, ...p);
  const app = appSupport(home, platform, env);
  const claudeDir = env.CLAUDE_CONFIG_DIR || h('.claude');
  const codexDir = env.CODEX_HOME || h('.codex');
  const docs = h('Documents');

  const locs = [
    // Credential stores first (expected locations, low risk)
    { path: path.join(claudeDir, '.credentials.json'), kind: 'credential-store', tool: 'Claude Code' },
    { path: path.join(codexDir, 'auth.json'), kind: 'credential-store', tool: 'Codex CLI' },
    { path: h('.local', 'share', 'opencode', 'auth.json'), kind: 'credential-store', tool: 'OpenCode' },
    { path: h('.gemini', 'oauth_creds.json'), kind: 'credential-store', tool: 'Gemini CLI' },

    // Agent and MCP configuration
    { path: h('.claude.json'), kind: 'agent-config', tool: 'Claude Code', expectedFields: ['primaryApiKey'] },
    { path: path.join(app, 'Claude', 'claude_desktop_config.json'), kind: 'agent-config', tool: 'Claude Desktop' },
    { path: h('.cursor', 'mcp.json'), kind: 'agent-config', tool: 'Cursor' },
    { path: h('.codeium', 'windsurf', 'mcp_config.json'), kind: 'agent-config', tool: 'Windsurf' },
    { path: h('.aider.conf.yml'), kind: 'agent-config', tool: 'Aider' },

    // Agent folders (history, settings, logs, shell snapshots)
    { path: claudeDir, kind: 'agent-data', tool: 'Claude Code', dir: true },
    { path: codexDir, kind: 'agent-data', tool: 'Codex CLI', dir: true },
    { path: h('.gemini'), kind: 'agent-data', tool: 'Gemini CLI', dir: true },
    { path: h('.local', 'share', 'opencode'), kind: 'agent-data', tool: 'OpenCode', dir: true },
    { path: h('.config', 'opencode'), kind: 'agent-data', tool: 'OpenCode', dir: true },
    { path: h('.continue'), kind: 'agent-data', tool: 'Continue', dir: true },
    { path: h('.cline', 'data'), kind: 'agent-data', tool: 'Cline CLI', dir: true },
    { path: h('.copilot'), kind: 'agent-data', tool: 'GitHub Copilot CLI', dir: true },
  ];

  // Editor storage: Cline, Roo Code and similar extensions keep task history
  // as JSON in globalStorage; editors keep chat state in state.vscdb databases.
  for (const editor of ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf', 'Antigravity']) {
    for (const store of ['globalStorage', 'workspaceStorage']) {
      locs.push({ path: path.join(app, editor, 'User', store), kind: 'editor-data', tool: `${editor} (${store})`, dir: true });
    }
  }

  locs.push(
    // Shell history
    { path: h('.bash_history'), kind: 'shell-history', tool: 'bash' },
    { path: h('.zsh_history'), kind: 'shell-history', tool: 'zsh' },
    { path: h('.local', 'share', 'fish', 'fish_history'), kind: 'shell-history', tool: 'fish' },
    { path: path.join(app, 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt'), kind: 'shell-history', tool: 'PowerShell' },
    // Shell startup files (keys exported here are common, and often synced in dotfile repos)
    { path: h('.bashrc'), kind: 'shell-config', tool: 'bash' },
    { path: h('.bash_profile'), kind: 'shell-config', tool: 'bash' },
    { path: h('.profile'), kind: 'shell-config', tool: 'sh' },
    { path: h('.zshrc'), kind: 'shell-config', tool: 'zsh' },
    { path: h('.zprofile'), kind: 'shell-config', tool: 'zsh' },
    { path: h('.zshenv'), kind: 'shell-config', tool: 'zsh' },
    { path: h('.config', 'fish', 'config.fish'), kind: 'shell-config', tool: 'fish' },
    // PowerShell profiles. On macOS, ~/Documents is privacy-protected: even
    // checking a path there makes the system ask for permission, so it is
    // only looked at on Windows, where the profile actually lives there.
    ...(platform === 'win32' ? [
      { path: path.join(docs, 'PowerShell', 'Microsoft.PowerShell_profile.ps1'), kind: 'shell-config', tool: 'PowerShell' },
      { path: path.join(docs, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'), kind: 'shell-config', tool: 'PowerShell' },
    ] : [
      { path: h('.config', 'powershell', 'Microsoft.PowerShell_profile.ps1'), kind: 'shell-config', tool: 'PowerShell' },
    ]),
    // Dotenv in home
    { path: h('.env'), kind: 'env', tool: 'dotenv' },
  );
  return locs;
}

// Files inside a project directory worth reading.
const PROJECT_NAMES = /^(\.env(\..+)?|\.envrc|\.mcp\.json|mcp\.json|Dockerfile(\..+)?|Containerfile|Makefile|Procfile|\.npmrc|\.pypirc|\.aider\.(chat|input)\.history(\.md)?)$/i;
const PROJECT_EXT = /\.(json|jsonl|json5|ya?ml|toml|ini|cfg|conf|properties|xml|gradle|kts|md|mdx|txt|log|js|mjs|cjs|jsx|ts|mts|cts|tsx|vue|svelte|astro|html?|py|ipynb|sh|zsh|bash|fish|ps1|bat|cmd|rb|go|java|kt|swift|php|cs|rs|dart|scala|lua|r|sql|env|tf|tfvars|tfstate|hcl|c|h|cc|cpp|cxx|hpp|hh|m|mm|pl|pm|ex|exs|erl|clj|groovy|jl|zig|nim|cr|elm|ml|fs|vb|ps|psm1)$/i;
const PROJECT_FILE = { test: (name) => PROJECT_NAMES.test(name) || PROJECT_EXT.test(name) };

// Third-party code and version-control internals. Build output (dist, build,
// .next, out) is deliberately scanned: a key there may be shipped to users.
// Python virtual environments are skipped by content (pyvenv.cfg), not by name.
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', '__pycache__', '.tox', '.terraform', '.cache', 'bower_components', '.pnpm-store', '.yarn']);

// Files read inside agent and editor folders.
const HISTORY_FILE = /\.(jsonl|json|md|txt|log|ya?ml|toml|sh|vscdb)$/i;

function projectKind(filename) {
  if (/^\.env(rc)?$|^\.env\.(?!example$|sample$|template$|dist$)[^.]+.*$/i.test(filename)) return 'env';
  if (/^(\.mcp|mcp)\.json$/i.test(filename) || filename === 'mcp_config.json') return 'agent-config';
  if (/\.aider\.(chat|input)\.history/i.test(filename)) return 'agent-data';
  // .env.example and friends are usually committed: a real key there is public.
  return 'project-file';
}

module.exports = { homeLocations, PROJECT_FILE, SKIP_DIRS, HISTORY_FILE, projectKind };
