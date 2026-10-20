'use strict';

// Static checks that enforce the design guarantees in SECURITY.md.
// If one of these fails, a change has weakened what users were promised.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SHIPPED = ['bin', 'src'].flatMap((d) =>
  fs.readdirSync(path.join(ROOT, d)).filter((f) => f.endsWith('.js')).map((f) => path.join(ROOT, d, f)));

const read = (f) => fs.readFileSync(f, 'utf8');

test('shipped code imports no network or process-spawning modules', () => {
  const banned = ['http', 'https', 'http2', 'net', 'tls', 'dgram', 'dns', 'child_process', 'worker_threads', 'cluster', 'inspector'];
  for (const f of SHIPPED) {
    const src = read(f);
    for (const m of banned) {
      const re = new RegExp(`require\\(\\s*['"](node:)?${m}['"]\\s*\\)|from\\s+['"](node:)?${m}['"]`);
      assert.ok(!re.test(src), `${path.relative(ROOT, f)} imports ${m}`);
    }
    assert.ok(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|\beval\s*\(|new Function\s*\(/.test(src.replace(/globalThis\.fetch = \(\) =>/, '')),
      `${path.relative(ROOT, f)} uses a network or eval primitive`);
  }
});

test('shipped code uses only an allowlist of read-only fs functions', () => {
  const allowed = new Set(['lstatSync', 'statSync', 'readdirSync', 'readFileSync', 'openSync', 'readSync', 'closeSync']);
  for (const f of SHIPPED) {
    const src = read(f);
    assert.ok(!/\bfs\s*\[/.test(src), `${path.relative(ROOT, f)} accesses fs dynamically`);
    assert.ok(!/require\(\s*['"](node:)?fs\/promises['"]\s*\)/.test(src), `${path.relative(ROOT, f)} imports fs/promises`);
    const requires = src.match(/require\(\s*['"](node:)?fs['"]\s*\)/g) || [];
    for (const r of requires) assert.match(src, /const fs = require\('fs'\);/, `${path.relative(ROOT, f)}: fs must be imported as "const fs"; found ${r}`);
    for (const m of src.matchAll(/\bfs\.(\w+)/g)) {
      assert.ok(allowed.has(m[1]), `${path.relative(ROOT, f)} uses fs.${m[1]}, which is not on the read-only allowlist`);
    }
  }
});

test('shipped code never writes to the filesystem', () => {
  const writers = /\bfs\.(write|append|rename|unlink|rm|rmdir|mkdir|mkdtemp|copyFile|cp|truncate|ftruncate|chmod|fchmod|lchmod|chown|fchown|lchown|symlink|link|utimes|futimes|lutimes|createWriteStream|createReadStream|promises)\w*/;
  for (const f of SHIPPED) assert.ok(!writers.test(read(f)), `${path.relative(ROOT, f)} uses a write API`);
});

test('files are only ever opened read-only', () => {
  for (const f of SHIPPED) {
    const src = read(f);
    const opens = src.match(/\bfs\.open\w*\s*\([^)]*\)/g) || [];
    for (const call of opens) {
      assert.match(call, /^fs\.openSync\(\s*[\w.]+\s*,\s*'r'\s*\)$/, `${path.relative(ROOT, f)}: ${call} must be fs.openSync(file, 'r')`);
    }
  }
});

test('package has zero runtime dependencies', () => {
  const pkg = JSON.parse(read(path.join(ROOT, 'package.json')));
  assert.deepStrictEqual(Object.keys(pkg.dependencies || {}), []);
  assert.deepStrictEqual(Object.keys(pkg.optionalDependencies || {}), []);
  assert.ok(!pkg.scripts || !pkg.scripts.postinstall, 'no install scripts');
  assert.ok(!pkg.scripts.preinstall && !pkg.scripts.install, 'no install scripts');
});

test('only bin/ and src/ code is published', () => {
  const pkg = JSON.parse(read(path.join(ROOT, 'package.json')));
  const code = pkg.files.filter((f) => f.endsWith('/'));
  assert.deepStrictEqual(code.sort(), ['bin/', 'src/']);
});

test('source files contain no invisible or direction-changing characters', () => {
  // Such characters can hide code from reviewers ("Trojan Source") and once
  // broke a regular expression in this project. Use \u escapes instead.
  const files = ['bin', 'src', 'test', 'scripts'].flatMap((d) =>
    fs.readdirSync(path.join(ROOT, d)).filter((f) => f.endsWith('.js')).map((f) => path.join(ROOT, d, f)));
  const bad = /[\u0080-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/;
  for (const f of files) {
    read(f).split('\n').forEach((line, i) => {
      assert.ok(!bad.test(line), `${path.relative(ROOT, f)}:${i + 1} contains an invisible or bidi character`);
    });
  }
});
