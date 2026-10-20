'use strict';

// Property-based test: instead of hand-picked examples, generate many random
// documents with known keys planted at random positions, separators, line
// endings, encodings, line lengths and read-chunk sizes. For every document
// the scanner must report exactly the planted keys (no misses, no extras, no
// duplicates) on exactly the right lines.
//
// The run is deterministic: a failure prints the seed and iteration, and
// FUZZ_SEED=<n> reproduces it. FUZZ_ITERATIONS raises the count locally.
require('./env-reset');
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { scan, fingerprint } = require('../src/scan');
const { tmpdir, write } = require('./helpers');

const SEED = Number(process.env.FUZZ_SEED || 20261020);
const ITERATIONS = Number(process.env.FUZZ_ITERATIONS || 400);

function prng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const URLSAFE = `${ALNUM}-_`;

function makeGenerators(r) {
  const s = (alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(r() * alphabet.length)]).join('');
  return [
    () => ['sk', 'ant', 'api03', `${s(URLSAFE, 93)}AA`].join('-'),
    () => ['sk', 'ant', 'oat01', `${s(URLSAFE, 93)}AA`].join('-'),
    () => ['sk', 'proj', s(URLSAFE, 100 + Math.floor(r() * 60))].join('-'),
    () => ['sk', 'or', 'v1', s(HEX, 64)].join('-'),
    () => `${'AI'}za${s(URLSAFE, 35)}`,
    () => `gsk_${s(ALNUM, 52)}`,
    () => `hf_${s(ALNUM, 34)}`,
    () => `xai-${s(ALNUM, 80)}`,
    () => `AK${'IA'}${s(UPPER, 16)}`,
    () => `gh${'p'}_${s(ALNUM, 36)}`,
    () => `sk-${s(ALNUM, 48)}`,
    () => `pplx-${s(ALNUM, 48)}`,
    () => `r8_${s(ALNUM, 37)}`,
    () => `github_pat_${s(`${ALNUM}_`, 82)}`,
    () => `AS${'IA'}${s(UPPER, 16)}`, // temporary AWS key; fresh file, so still reported
    () => `sk-${s(ALNUM, 20)}T3Blbk${'FJ'}${s(ALNUM, 20)}`,
  ];
}

// Characters that may legally sit right before / after a key in real files.
const LEFT = ['', ' ', '"', "'", '=', ': ', '\\n', '\\t', '\\r\\n', '%22', '%3D', '\\u0022', '(', '`', '\t', ',', '[', '<'];
const RIGHT = ['', ' ', '"', "'", ',', ')', '`', '\\n', '%22', ';', ']', '>', '\\u0022'];
const WORDS = ['the', 'agent', 'said', 'ok', 'let', 'me', 'check', 'config', 'çalış', 'größe', '日本', '🙂', '{"a":1}', 'x=1', 'sk', 'ask-me', 'task-1', 'AI', 'risk-free', 'hf', 'pk'];

function filler(r, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(WORDS[Math.floor(r() * WORDS.length)]);
  return out.join(' ');
}

function buildDocument(r) {
  const gens = makeGenerators(r);
  const lines = [];
  const planted = []; // { key, line }
  const lineCount = 1 + Math.floor(r() * 40);
  for (let i = 0; i < lineCount; i++) {
    const long = r() < 0.08;
    let line = filler(r, long ? 1500 + Math.floor(r() * 3000) : Math.floor(r() * 40));
    if (r() < 0.45) {
      const key = gens[Math.floor(r() * gens.length)]();
      const pos = Math.floor(r() * (line.length + 1));
      // never split a multi-unit character (emoji) when inserting
      const safePos = line.slice(0, pos).replace(/[\ud800-\udbff]$/, '').length;
      let left = LEFT[Math.floor(r() * LEFT.length)];
      let right = RIGHT[Math.floor(r() * RIGHT.length)];
      const before = line.slice(0, safePos);
      const after = line.slice(safePos);
      if (left === '' && before && /[A-Za-z0-9]$/.test(before)) left = ' ';
      if (right === '' && after && /^[A-Za-z0-9_-]/.test(after)) right = ' ';
      line = `${before}${left}${key}${right}${after}`;
      planted.push({ key, line: i + 1 });
    }
    lines.push(line);
  }
  const eol = r() < 0.3 ? '\r\n' : '\n';
  return { text: lines.join(eol) + (r() < 0.5 ? eol : ''), planted };
}

function encode(r, text) {
  const roll = r();
  if (roll < 0.12) return { buf: Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]), label: 'utf16le+bom' };
  if (roll < 0.18) return { buf: Buffer.from(text, 'utf16le'), label: 'utf16le' };
  if (roll < 0.30) {
    // binary-looking file: NUL bytes sprinkled between lines
    return { buf: Buffer.from(text.replace(/\n/g, '\n\u0000\u0000'), 'utf8'), label: 'binary' };
  }
  return { buf: Buffer.from(text, 'utf8'), label: 'utf8' };
}

test(`fuzz: ${ITERATIONS} random documents, every planted key found exactly once on the right line (seed ${SEED})`, () => {
  const r = prng(SEED);
  const root = tmpdir('klc-fuzz-');
  let planted = 0;
  for (let i = 0; i < ITERATIONS; i++) {
    const doc = buildDocument(r);
    const enc = encode(r, doc.text);
    const dir = path.join(root, String(i));
    write(path.join(dir, 'doc.txt'), enc.buf);
    const chunkBytes = [64, 97, 256, 1000, 1024, 4096, 65536][Math.floor(r() * 7)];
    const res = scan({ home: false, project: dir, chunkBytes });

    const expected = new Map();
    for (const p of doc.planted) {
      const fp = fingerprint(p.key);
      if (!expected.has(fp)) expected.set(fp, []);
      expected.get(fp).push(p.line);
    }
    const ctx = `seed ${SEED}, iteration ${i}, encoding ${enc.label}, chunk ${chunkBytes}`;
    assert.deepStrictEqual(
      res.findings.map((f) => f.fingerprint).sort(),
      [...expected.keys()].sort(),
      `wrong set of keys (${ctx})`,
    );
    for (const f of res.findings) {
      const want = expected.get(f.fingerprint).sort((a, b) => a - b);
      const got = f.occurrences.map((o) => o.line).sort((a, b) => a - b);
      // The scanner treats a file as binary when its first 8 KB contain a NUL byte.
      const isBinary = enc.label === 'binary' && enc.buf.subarray(0, 8192).includes(0);
      if (isBinary) {
        // binary files report no line numbers, only how often a key occurs
        assert.strictEqual(got.length, want.length, `wrong count for ${f.provider} (${ctx})`);
        assert.ok(got.every((l) => l === null), `binary file reported line numbers (${ctx})`);
      } else {
        assert.deepStrictEqual(got, want, `wrong lines for ${f.provider} (${ctx})`);
      }
    }
    assert.ok(res.complete, `scan reported incomplete (${ctx})`);
    planted += doc.planted.length;
  }
  assert.ok(planted > ITERATIONS / 2, 'the generator planted keys');
});
