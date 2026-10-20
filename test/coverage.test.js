'use strict';

// Coverage, classification and usability tests added in the full review.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
require('./env-reset');
const { scan, gitIgnored } = require('../src/scan');
const { homeLocations } = require('../src/locations');
const { fakeKeys, tmpdir, write } = require('./helpers');

const BIN = path.join(__dirname, '..', 'bin', 'keyleakcheck.js');
const appDir = (home) => (process.platform === 'darwin' ? path.join(home, 'Library', 'Application Support')
  : process.platform === 'win32' ? path.join(home, 'AppData', 'Roaming') : path.join(home, '.config'));

function run(args, home, extraEnv = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    env: { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData', 'Roaming'), XDG_CONFIG_HOME: '', NO_COLOR: '1', ...extraEnv },
    encoding: 'utf8',
  });
}
const kinds = (r) => r.findings.map((f) => `${f.provider}|${f.severity}`).sort();

test('Claude login tokens: high in history, low in the credentials file', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-oat-');
  write(path.join(home, '.claude', '.credentials.json'), JSON.stringify({ claudeAiOauth: { accessToken: k.oauth } }));
  let r = scan({ homeDir: home, project: null });
  assert.deepStrictEqual(kinds(r), ['Anthropic (Claude login token)|low']);
  write(path.join(home, '.claude', 'projects', 'p', 's.jsonl'), `${JSON.stringify({ c: `token ${k.oauth}` })}\n`);
  r = scan({ homeDir: home, project: null });
  assert.deepStrictEqual(kinds(r), ['Anthropic (Claude login token)|high']);
});

test('~/.claude.json: primaryApiKey is expected (low), an MCP env key is exposed (high)', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-cj-');
  write(path.join(home, '.claude.json'), JSON.stringify({ primaryApiKey: k.anthropic, mcpServers: { s: { env: { OPENAI_API_KEY: k.openai } } } }, null, 2));
  const r = scan({ homeDir: home, project: null });
  assert.deepStrictEqual(kinds(r), ['Anthropic|low', 'OpenAI|high']);
});

test('shell startup files are scanned (medium risk)', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-rc-');
  write(path.join(home, '.zshrc'), `export OPENAI_API_KEY=${k.openai}\n`);
  const r = scan({ homeDir: home, project: null });
  assert.deepStrictEqual(kinds(r), ['OpenAI|medium']);
  assert.strictEqual(r.grade, 'B');
});

test('Cline task history in editor storage and editor databases are scanned', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-ed-');
  const app = appDir(home);
  write(path.join(app, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'tasks', '1', 'api_conversation_history.json'), JSON.stringify([{ text: `use ${k.openai}` }]));
  write(path.join(app, 'Cursor', 'User', 'workspaceStorage', 'abc', 'state.vscdb'), Buffer.concat([Buffer.from('SQLite format 3\0\0\0'), Buffer.from(`{"t":"${k.google}"}`), Buffer.alloc(16)]));
  const r = scan({ homeDir: home, project: null, env: { APPDATA: path.join(home, 'AppData', 'Roaming') } });
  assert.deepStrictEqual(r.findings.map((f) => f.provider).sort(), ['Google (Gemini / Cloud)', 'OpenAI']);
  assert.ok(r.findings.every((f) => f.occurrences[0].kind === 'editor-data'));
});

test('CLAUDE_CONFIG_DIR and CODEX_HOME are honoured', () => {
  const locs = homeLocations('/h', 'linux', { CLAUDE_CONFIG_DIR: '/custom/claude', CODEX_HOME: '/custom/codex' });
  const paths = locs.map((l) => l.path);
  assert.ok(paths.includes(path.join('/custom/claude', '.credentials.json')));
  assert.ok(paths.includes('/custom/claude'));
  assert.ok(paths.includes(path.join('/custom/codex', 'auth.json')));
});

test('a known agent folder that is itself a symlink is followed', (t) => {
  const k = fakeKeys();
  const home = tmpdir('klc-slh-');
  const real = tmpdir('klc-dot-');
  write(path.join(real, 'projects', 'p', 's.jsonl'), `${JSON.stringify({ c: `\n${k.openai}` })}\n`);
  try { fs.symlinkSync(real, path.join(home, '.claude'), 'dir'); } catch { t.skip('symlinks not permitted here'); return; }
  const r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings.length, 1);
});

test('UTF-16 files (Windows PowerShell 5.1 default) are decoded and scanned', () => {
  const k = fakeKeys();
  const project = tmpdir('klc-u16-');
  write(path.join(project, 'notes.txt'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`line1\r\nOPENAI_API_KEY=${k.openai}\r\n`, 'utf16le')]));
  const be = Buffer.from(`x\nKEY=${k.google}\n`, 'utf16le').swap16();
  write(path.join(project, 'be.txt'), Buffer.concat([Buffer.from([0xfe, 0xff]), be]));
  write(path.join(project, 'nobom.txt'), Buffer.from(`hello there friend\nKEY=${k.openrouter}\n`, 'utf16le'));
  const r = scan({ home: false, project });
  assert.deepStrictEqual(r.findings.map((f) => f.provider).sort(), ['Google (Gemini / Cloud)', 'OpenAI', 'OpenRouter']);
  const openai = r.findings.find((f) => f.provider === 'OpenAI');
  assert.strictEqual(openai.occurrences[0].line, 2);
});

test('.env.example with a real key is high risk; .envrc is treated as an env file', () => {
  const k = fakeKeys();
  const project = tmpdir('klc-ex-');
  write(path.join(project, '.gitignore'), '.env*\n!.env.example\n');
  write(path.join(project, '.env.example'), `OPENAI_API_KEY=${k.openai}\n`);
  write(path.join(project, '.envrc'), `export GEMINI_API_KEY=${k.google}\n`);
  const r = scan({ home: false, project });
  assert.deepStrictEqual(kinds(r), ['Google (Gemini / Cloud)|medium', 'OpenAI|high']);
});

test('build output is scanned; Python virtualenvs are skipped by content, not by name', () => {
  const k = fakeKeys();
  const project = tmpdir('klc-dirs-');
  write(path.join(project, 'dist', 'main.js'), `const k="${k.google}";`);
  write(path.join(project, 'config', 'env', 'prod.js'), `module.exports={k:"${k.openai}"}`);
  write(path.join(project, '.venv', 'pyvenv.cfg'), 'home = /usr/bin\n');
  write(path.join(project, '.venv', 'lib', 'site.py'), `K="${k.openrouter}"`);
  write(path.join(project, '.next', 'cache', 'x.json'), `"${k.anthropic}"`);
  const r = scan({ home: false, project });
  assert.deepStrictEqual(r.findings.map((f) => f.provider).sort(), ['Google (Gemini / Cloud)', 'OpenAI']);
});

test('.gitignore: folder rules, path rules, globstar, info/exclude, global excludes and negation', () => {
  const home = tmpdir('klc-gh-');
  const root = tmpdir('klc-gr-');
  const f = (...p) => path.join(root, ...p);
  write(f('a', 'secrets', '.env'), 'x');
  write(f('apps', 'api', '.env'), 'x');
  write(f('deep', 'x', 'y', '.env.local'), 'x');
  write(f('info', '.env'), 'x');
  write(f('global', '.env'), 'x');
  write(f('plain', '.env'), 'x');
  write(f('.gitignore'), 'secrets/\napps/api/.env\n**/*.local\n');
  write(f('.git', 'info', 'exclude'), 'info/.env\n');
  write(path.join(home, '.config', 'git', 'ignore'), 'global/\n');
  const ignored = (...p) => gitIgnored(f(...p), root, home);
  assert.strictEqual(ignored('a', 'secrets', '.env'), true, 'folder rule');
  assert.strictEqual(ignored('apps', 'api', '.env'), true, 'path rule');
  assert.strictEqual(ignored('deep', 'x', 'y', '.env.local'), true, 'globstar');
  assert.strictEqual(ignored('info', '.env'), true, '.git/info/exclude');
  assert.strictEqual(ignored('global', '.env'), true, 'global excludes file');
  assert.strictEqual(ignored('plain', '.env'), false, 'not ignored');
  write(f('apps', 'api', '.gitignore'), '!.env\n');
  assert.strictEqual(ignored('apps', 'api', '.env'), false, 'negation in a deeper .gitignore');
});

test('--path to a missing folder is an error, and --path to a single file scans that file', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-p-');
  const missing = run(['--no-home', '--path', path.join(home, 'nope')], home);
  assert.strictEqual(missing.status, 2);
  assert.match(missing.stderr, /Path not found/);
  const file = path.join(tmpdir('klc-pf-'), 'config.yaml');
  write(file, `key: ${k.openai}\n`);
  const one = run(['--no-home', '--path', file], home);
  assert.strictEqual(one.status, 1);
  assert.match(one.stdout, /config\.yaml:1/);
});

test('folders that cannot be listed are reported and make the scan partial', { skip: process.platform === 'win32' || (process.getuid && process.getuid() === 0) }, () => {
  const project = tmpdir('klc-perm-');
  const locked = path.join(project, 'locked');
  write(path.join(locked, 'a.txt'), 'x');
  fs.chmodSync(locked, 0o000);
  try {
    const r = scan({ home: false, project });
    assert.strictEqual(r.complete, false);
    assert.strictEqual(r.skipped[0].reason, 'folder-permission-denied');
  } finally {
    fs.chmodSync(locked, 0o755);
  }
});

test('folders that contain the home folder are not walked as a project', () => {
  const home = path.join(tmpdir('klc-parent-'), 'me');
  fs.mkdirSync(home);
  const r = scan({ homeDir: home, project: path.dirname(home) });
  assert.strictEqual(r.projectSkipped, path.dirname(home));
});

test('JSON output escapes bidirectional override characters', () => {
  const k = fakeKeys();
  const project = tmpdir('klc-bidi-');
  write(path.join(project, 'a\u202eb.txt'), `k=${k.openai}\n`);
  const r = run(['--no-home', '--path', project, '--json'], tmpdir('klc-h-'));
  assert.ok(!r.stdout.includes('\u202e'));
  assert.ok(r.stdout.includes('\\u202e'));
  JSON.parse(r.stdout);
});

test('piping into a command that closes early does not print an error', { skip: process.platform === 'win32' }, () => {
  const home = tmpdir('klc-pipe-');
  const r = spawnSync('sh', ['-c', `"${process.execPath}" "${BIN}" --help | head -c 5 >/dev/null`], { encoding: 'utf8', env: { ...process.env, HOME: home } });
  assert.strictEqual(r.stderr, '');
});

test('the entropy filter keeps real keys of every shape (short, long, hex-only)', () => {
  const { isPlaceholder } = require('../src/patterns');
  let seed = 12345;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const pick = (alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');
  let rejected = 0;
  for (let i = 0; i < 20000; i++) {
    if (isPlaceholder(`AKIA${pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}`)) rejected++;
    if (isPlaceholder(`AIza${pick('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', 35)}`)) rejected++;
    if (isPlaceholder(`sk-or-v1-${pick('0123456789abcdef', 64)}`)) rejected++;
    if (isPlaceholder(`hf_${pick('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 34)}`)) rejected++;
  }
  assert.strictEqual(rejected, 0);
  assert.ok(isPlaceholder('AKIAAAAAAAAAAAAAAAAA'));
  assert.ok(isPlaceholder(`sk-proj-${'ab'.repeat(20)}`));
});

void os;

test('--list-locations reads no file contents', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-list-');
  write(path.join(home, '.claude', 'projects', 'p', 's.jsonl'), k.openai);
  write(path.join(home, '.zshrc'), k.google);
  const calls = { openSync: 0, readFileSync: 0, readSync: 0 };
  const saved = {};
  for (const name of Object.keys(calls)) {
    saved[name] = fs[name];
    fs[name] = (...a) => { calls[name]++; return saved[name](...a); };
  }
  try {
    const { listLocations } = require('../src/scan');
    const r = listLocations({ homeDir: home, project: null });
    assert.ok(r.coverage.some((l) => l.present));
  } finally {
    for (const name of Object.keys(saved)) fs[name] = saved[name];
  }
  assert.deepStrictEqual(calls, { openSync: 0, readFileSync: 0, readSync: 0 });
});

test('every location documented in the README is in the scan list', () => {
  const home = '/h';
  const paths = homeLocations(home, 'linux', {}).map((l) => l.path.split(path.sep).join('/'));
  const documented = [
    '/h/.claude', '/h/.claude/.credentials.json', '/h/.claude.json', '/h/.codex', '/h/.codex/auth.json',
    '/h/.config/Claude/claude_desktop_config.json', '/h/.cursor/mcp.json', '/h/.codeium/windsurf/mcp_config.json',
    '/h/.gemini', '/h/.local/share/opencode', '/h/.continue', '/h/.cline/data', '/h/.copilot', '/h/.config/Antigravity/User/globalStorage',
    '/h/.config/Code/User/globalStorage', '/h/.config/Cursor/User/workspaceStorage',
    '/h/.bash_history', '/h/.zsh_history', '/h/.local/share/fish/fish_history', '/h/.zshrc', '/h/.bashrc', '/h/.env',
  ];
  for (const d of documented) assert.ok(paths.includes(d), `missing location ${d}`);
  const mac = homeLocations('/h', 'darwin', {}).map((l) => l.path);
  assert.ok(mac.includes(path.join('/h', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')));
  const win = homeLocations('C:\\Users\\a', 'win32', { APPDATA: 'C:\\Users\\a\\AppData\\Roaming' }).map((l) => l.path);
  assert.ok(win.some((p) => p.includes('PSReadLine')));
});

test('the CLI installs the fetch tripwire before loading anything else', () => {
  const src = fs.readFileSync(BIN, 'utf8');
  const tripwire = src.indexOf('globalThis.fetch = () =>');
  const firstRequire = src.indexOf('require(');
  assert.ok(tripwire > 0 && tripwire < firstRequire);
});

test('placeholder words count only as separate segments, never inside a random key', () => {
  const { isPlaceholder } = require('../src/patterns');
  assert.ok(isPlaceholder('sk-proj-your-api-key-goes-here'));
  assert.ok(isPlaceholder('sk-proj-YOUR_OPENAI_API_KEY_HERE'));
  assert.ok(isPlaceholder('sk-ant-api03-REPLACE_WITH_YOUR_KEY_REPLACE_WITH_YOUR_KEY_REPLACE_WITH_YOUR_KEY_X'));
  // Real keys that happen to contain such letters must be kept (found by the randomised test, seed 8).
  assert.ok(!isPlaceholder(`sk-proj-Zq81K3dumMyq0Lp${'A9fZ'.repeat(5)}ExampleQ7r`));
  assert.ok(!isPlaceholder('AIzaSyDX9fQ2kLmPlaceholdeRz8Vt0Ywq7Nn3c'));
  assert.ok(!isPlaceholder(`sk-proj-${'Qz81'.repeat(6)}-my-${'Lp0A'.repeat(6)}_key_${'9fZx'.repeat(5)}`));
});

test('macOS: no location inside privacy-protected folders (no permission prompts)', () => {
  const protectedDirs = ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Movies', 'Music'].map((d) => path.join('/Users/a', d));
  const mac = homeLocations('/Users/a', 'darwin', {}).map((l) => l.path);
  for (const p of mac) assert.ok(!protectedDirs.some((d) => p.startsWith(d)), `${p} is in a macOS protected folder`);
  const win = homeLocations('C:\\Users\\a', 'win32', { APPDATA: 'C:\\Users\\a\\AppData\\Roaming' }).map((l) => l.path);
  assert.ok(win.some((p) => p.includes('WindowsPowerShell')));
});

// Regression tests from the first run on a real Mac (October 2026).

test('keys inside an embedded browser profile are low risk and explained', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-browser-');
  const profile = path.join(home, '.gemini', 'antigravity-browser-profile');
  write(path.join(profile, 'Local State'), '{}');
  write(path.join(profile, 'Default', 'shared_proto_db', '000003.log'), Buffer.concat([Buffer.from([0, 1, 0]), Buffer.from(`${k.google}\u0000${k.google}`)]));
  const r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].severity, 'low');
  assert.strictEqual(r.findings[0].occurrences[0].kind, 'browser-data');
  assert.strictEqual(r.grade, 'A');
  const cli = run(['--no-project'], home);
  assert.strictEqual(cli.status, 0);
  assert.match(cli.stdout, /browser cache/);
  assert.match(cli.stdout, /000003\.log \(2 times\)/);
  // The same key in a real transcript is still high risk.
  write(path.join(home, '.gemini', 'tmp', 'chat.json'), JSON.stringify({ text: k.google }));
  assert.strictEqual(scan({ homeDir: home, project: null }).findings[0].severity, 'high');
});

test('temporary AWS keys: high while they can still work, low once expired', () => {
  const home = tmpdir('klc-sts-');
  const key = `AS${'IA'}QW3RTY5UIOPA7SDF`;
  const file = path.join(home, '.codex', 'sessions', '2026', 's.jsonl');
  write(file, `${JSON.stringify({ out: `AWS_ACCESS_KEY_ID=${key}` })}\n`);
  let r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings[0].provider, 'AWS (temporary credential)');
  assert.strictEqual(r.findings[0].severity, 'high');
  const old = new Date(Date.now() - 40 * 24 * 3600 * 1000);
  fs.utimesSync(file, old, old);
  r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings[0].severity, 'low');
  assert.match(r.findings[0].occurrences[0].note, /expired/);
  assert.strictEqual(r.grade, 'A');
});

test('repeated occurrences in one file are reported on one line', () => {
  const k = fakeKeys();
  const home = tmpdir('klc-group-');
  write(path.join(home, '.zsh_history'), Array.from({ length: 8 }, () => `export K=${k.openai}`).join('\n'));
  const cli = run(['--no-project'], home);
  assert.match(cli.stdout, /\.zsh_history:1, 2, 3 \(\+5 more\)/);
});
