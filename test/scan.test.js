'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
require('./env-reset');
const { scan } = require('../src/scan');
const { findSecrets } = require('../src/patterns');
const { fakeKeys, tmpdir, write } = require('./helpers');

const BIN = path.join(__dirname, '..', 'bin', 'keyleakcheck.js');

function fixture() {
  const k = fakeKeys();
  const home = tmpdir('klc-home-');
  const project = tmpdir('klc-proj-');
  // Claude Code history with a pasted key on line 2
  write(path.join(home, '.claude', 'projects', 'demo', 'session.jsonl'),
    `{"role":"user","content":"hi"}\n{"role":"user","content":"use ${k.anthropic} please"}\n`);
  // MCP config with an env key
  write(path.join(home, '.cursor', 'mcp.json'),
    JSON.stringify({ mcpServers: { x: { env: { OPENAI_API_KEY: k.openai } } } }, null, 2));
  // Same Anthropic key again in shell history (should de-duplicate)
  write(path.join(home, '.zsh_history'), `export ANTHROPIC_API_KEY=${k.anthropic}\n`);
  // Project .env that is NOT gitignored
  write(path.join(project, '.env'), `GEMINI_API_KEY=${k.google}\n`);
  // Placeholders must be ignored
  write(path.join(project, 'README.md'), 'OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nKEY=sk-your-api-key\n');
  // node_modules must be skipped
  write(path.join(project, 'node_modules', 'pkg', 'index.js'), `const k = "${k.openrouter}";\n`);
  return { k, home, project };
}

function run(args, home) {
  return spawnSync(process.execPath, [BIN, ...args], {
    env: { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData', 'Roaming'), NO_COLOR: '1' },
    encoding: 'utf8',
  });
}

test('finds keys in agent history, MCP config, shell history and .env', () => {
  const { home, project } = fixture();
  const r = scan({ homeDir: home, project });
  const providers = r.findings.map((f) => f.provider).sort();
  assert.deepStrictEqual(providers, ['Anthropic', 'Google (Gemini / Cloud)', 'OpenAI']);
  const anth = r.findings.find((f) => f.provider === 'Anthropic');
  assert.strictEqual(anth.occurrences.length, 2, 'same key in two files is one finding');
  const hist = anth.occurrences.find((o) => o.kind === 'agent-data');
  assert.strictEqual(hist.line, 2);
  const env = r.findings.find((f) => f.provider.startsWith('Google'));
  assert.strictEqual(env.severity, 'high', 'non-gitignored .env is high risk');
  assert.strictEqual(r.grade, 'D');
});

test('gitignored .env is medium risk', () => {
  const { home, project } = fixture();
  write(path.join(project, '.gitignore'), 'node_modules\n.env\n');
  const r = scan({ homeDir: home, project, home: false });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].severity, 'medium');
  assert.strictEqual(r.grade, 'B');
});

// Regression tests for gaps found in adversarial verification.

test('finds keys right after JSON escapes such as \\n and \\t in agent transcripts', () => {
  const { k } = fixture();
  const home = tmpdir('klc-esc-');
  write(path.join(home, '.claude', 'projects', 'p', 's.jsonl'),
    `${JSON.stringify({ content: `my key:\n${k.openai}` })}\n${JSON.stringify({ content: `\t${k.google}` })}\n${JSON.stringify({ content: `a\r\n${k.anthropic}` })}\n`);
  const r = scan({ homeDir: home, project: null });
  assert.deepStrictEqual(r.findings.map((f) => f.provider).sort(), ['Anthropic', 'Google (Gemini / Cloud)', 'OpenAI']);
});

test('does not match keys glued to other letters', () => {
  const { k } = fixture();
  assert.strictEqual(findSecrets(`abc${k.openai}`).length, 0);
});

test('reads dotfiles that are symlinks to files', (t) => {
  const { k } = fixture();
  const home = tmpdir('klc-link-');
  const real = path.join(tmpdir('klc-dotfiles-'), 'zsh_history');
  write(real, `export ANTHROPIC_API_KEY=${k.anthropic}\n`);
  try { fs.symlinkSync(real, path.join(home, '.zsh_history'), 'file'); } catch { t.skip('symlinks not permitted here'); return; }
  const r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].provider, 'Anthropic');
});

test('a nested .env covered by a parent .gitignore is medium, and negation is honoured', () => {
  const { k } = fixture();
  const project = tmpdir('klc-nested-');
  write(path.join(project, '.gitignore'), 'node_modules/\n**/.env\n');
  write(path.join(project, 'apps', 'api', '.env'), `KEY=${k.openrouter}\n`);
  let r = scan({ home: false, project });
  assert.strictEqual(r.findings[0].severity, 'medium');
  write(path.join(project, 'apps', 'api', '.gitignore'), '!.env\n');
  r = scan({ home: false, project });
  assert.strictEqual(r.findings[0].severity, 'high');
});

test('masks show only the fixed provider prefix and the last 4 characters', () => {
  const { k } = fixture();
  const { mask } = require('../src/scan');
  assert.strictEqual(mask(k.openai), `sk-proj-…${k.openai.slice(-4)}`);
  assert.strictEqual(mask(k.anthropic), `sk-ant-api03-…${k.anthropic.slice(-4)}`);
  assert.strictEqual(mask(k.google), `AIza…${k.google.slice(-4)}`);
  assert.strictEqual(mask(k.openrouter), `sk-or-v1-…${k.openrouter.slice(-4)}`);
});

// Regression tests for the second review.

test('scans files larger than one chunk, including keys on chunk edges and in one huge line', () => {
  const { k } = fixture();
  const home = tmpdir('klc-big-');
  const filler = `${'{"c":"lorem ipsum dolor sit amet"}\n'.repeat(3000)}`; // ~105 KB
  // Key A on its own line near a chunk boundary, key B at the very end,
  // key C inside one 300 KB line that has no newline at all.
  const longLine = `${'abc '.repeat(40000)}${k.google}${' xyz'.repeat(35000)}\n`;
  const content = `${filler}${JSON.stringify({ c: `\n${k.openai}` })}\n${filler}${longLine}${filler}key=${k.anthropic}`;
  write(path.join(home, '.claude', 'projects', 'p', 'big.jsonl'), content);
  const r = scan({ homeDir: home, project: null, chunkBytes: 64 * 1024 });
  assert.deepStrictEqual(r.findings.map((f) => f.provider).sort(), ['Anthropic', 'Google (Gemini / Cloud)', 'OpenAI']);
  assert.ok(r.complete);
  const expectedLine = (needle) => content.slice(0, content.indexOf(needle)).split('\n').length;
  for (const f of r.findings) {
    const key = Object.values(k).find((v) => f.masked.endsWith(v.slice(-4)));
    assert.strictEqual(f.occurrences[0].line, expectedLine(key), `line number for ${f.provider}`);
  }
  assert.strictEqual(r.findings.length, 3, 'no duplicate or partial matches across chunks');
});

test('files over --max-file-mb are reported, make the scan partial and exit with code 3', () => {
  const home = tmpdir('klc-cap-');
  write(path.join(home, '.zsh_history'), 'x'.repeat(2 * 1024 * 1024));
  const r = scan({ homeDir: home, project: null, maxBytes: 1024 * 1024 });
  assert.strictEqual(r.complete, false);
  assert.strictEqual(r.skipped[0].reason, 'too-large');
  const cli = run(['--no-project', '--max-file-mb', '1'], home);
  assert.strictEqual(cli.status, 3);
  assert.match(cli.stdout, /could not be scanned/);
  assert.match(cli.stdout, /partial scan/);
});

test('reports when the file limit stops a walk', () => {
  const project = tmpdir('klc-many-');
  for (let i = 0; i < 20; i++) write(path.join(project, `f${i}.txt`), 'hello');
  const r = scan({ home: false, project, maxFiles: 5 });
  assert.strictEqual(r.truncated, true);
  assert.strictEqual(r.complete, false);
});

test('does not walk the home folder as a project unless asked with --path', () => {
  const { k } = fixture();
  const home = tmpdir('klc-cwdhome-');
  write(path.join(home, 'Documents', 'notes.txt'), `key ${k.openai}`);
  const r = scan({ homeDir: home, project: home });
  assert.strictEqual(r.projectSkipped, home);
  assert.strictEqual(r.findings.length, 0);
  const explicit = scan({ homeDir: home, project: home, projectExplicit: true });
  assert.strictEqual(explicit.findings.length, 1);
});

test('ignores findings listed in .keyleakcheckignore or passed with --ignore', () => {
  const { k } = fixture();
  const project = tmpdir('klc-ign-');
  write(path.join(project, 'test', 'fixtures.js'), `const a = "${k.openai}";\nconst b = "${k.google}";\n`);
  const first = scan({ home: false, project });
  assert.strictEqual(first.findings.length, 2);
  const [a, b] = first.findings.map((f) => f.fingerprint);
  write(path.join(project, '.keyleakcheckignore'), `# test fixtures\n${a}\n`);
  const second = scan({ home: false, project });
  assert.deepStrictEqual(second.findings.map((f) => f.fingerprint), [b]);
  assert.strictEqual(second.ignored, 1);
  const third = run(['--no-home', '--path', project, '--ignore', b], tmpdir('klc-h-'));
  assert.strictEqual(third.status, 0);
  assert.match(third.stdout, /2 occurrence\(s\) ignored/);
});

test('strips terminal control and bidi characters from printed file names', { skip: process.platform === 'win32' }, () => {
  const { k } = fixture();
  const project = tmpdir('klc-ansi-');
  write(path.join(project, 'evil\x1b[2J\x1b[32mclean\u202e.txt'), `k=${k.openai}\n`);
  const r = run(['--no-home', '--path', project], tmpdir('klc-h-'));
  assert.strictEqual(r.status, 1);
  assert.ok(!r.stdout.includes('\x1b'), 'no escape sequences in output');
  assert.ok(!r.stdout.includes('\u202e'), 'no bidi override in output');
  assert.match(r.stdout, /evil\?\[2J\?\[32mclean\?\.txt/);
});

test('keys in expected credential stores do not lower the grade', () => {
  const { k } = fixture();
  const home = tmpdir('klc-store-');
  write(path.join(home, '.codex', 'auth.json'), JSON.stringify({ OPENAI_API_KEY: k.openai }));
  const r = scan({ homeDir: home, project: null });
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].severity, 'low');
  assert.strictEqual(r.grade, 'A');
});

test('ignores placeholders and low-entropy samples', () => {
  assert.strictEqual(findSecrets('sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx').length, 0);
  assert.strictEqual(findSecrets('sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa').length, 0);
  assert.strictEqual(findSecrets('OPENAI_API_KEY=<your-key>').length, 0);
});

test('never prints a full key in text, JSON or card output', () => {
  const { k, home, project } = fixture();
  for (const args of [[], ['--json'], ['--card']]) {
    const r = run([...args, '--path', project], home);
    const out = r.stdout + r.stderr;
    for (const key of Object.values(k)) {
      assert.ok(!out.includes(key), `full key leaked in output of ${args.join(' ') || 'text'}`);
      assert.ok(!out.includes(key.slice(12, 40)), 'key body leaked');
    }
  }
});

test('card output contains no file paths', () => {
  const { home, project } = fixture();
  const r = run(['--card', '--path', project], home);
  assert.ok(!r.stdout.includes(home) && !r.stdout.includes(project));
  assert.match(r.stdout, /Grade D/);
});

test('is read-only: no file is created, changed or removed', () => {
  const { home, project } = fixture();
  const snapshot = (dir) => {
    const out = {};
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else { const s = fs.statSync(p); out[p] = `${s.size}:${s.mtimeMs}:${fs.readFileSync(p, 'utf8')}`; }
      }
    };
    walk(dir);
    return out;
  };
  const before = { ...snapshot(home), ...snapshot(project) };
  run(['--path', project], home);
  run(['--json', '--path', project], home);
  const after = { ...snapshot(home), ...snapshot(project) };
  assert.deepStrictEqual(after, before);
});

test('exit code is 1 with high-risk keys and 0 when clean', () => {
  const { home, project } = fixture();
  assert.strictEqual(run(['--path', project], home).status, 1);
  const cleanHome = tmpdir('klc-clean-');
  const cleanProject = tmpdir('klc-cleanp-');
  const r = run(['--path', cleanProject], cleanHome);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /Grade: A/);
});

test('rejects unknown options with exit code 2', () => {
  const r = run(['--upload'], tmpdir('klc-x-'));
  assert.strictEqual(r.status, 2);
});

test('finds keys inside binary files such as editor databases, and says so', () => {
  const { k } = fixture();
  const project = tmpdir('klc-bin-');
  write(path.join(project, 'blob.json'), Buffer.concat([Buffer.from([0, 1, 2, 0]), Buffer.from(k.openai), Buffer.from([0, 0])]));
  const r = scan({ home: false, project });
  assert.strictEqual(r.findings.length, 1);
  assert.match(r.findings[0].occurrences[0].note, /binary/);
});

test('does not follow symlinked directories found inside a scanned folder', (t) => {
  const { k } = fixture();
  const project = tmpdir('klc-sl-');
  const outside = tmpdir('klc-outside-');
  write(path.join(outside, 'secret.txt'), k.openai);
  try { fs.symlinkSync(outside, path.join(project, 'link'), 'dir'); } catch { t.skip('symlinks not permitted here'); return; }
  const r = scan({ home: false, project });
  assert.strictEqual(r.findings.length, 0);
});

