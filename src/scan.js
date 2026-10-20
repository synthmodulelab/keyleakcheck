'use strict';

// Read-only scanner. The only fs functions used are lstatSync, statSync,
// readdirSync, readFileSync, openSync(file, 'r'), readSync and closeSync
// (enforced by test/guarantees.test.js). It never writes, renames, deletes or
// opens a socket.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { findSecrets, KNOWN_PREFIX } = require('./patterns');
const { homeLocations, PROJECT_FILE, SKIP_DIRS, HISTORY_FILE, projectKind } = require('./locations');

const SEVERITY = {
  'agent-data': 'high',
  'agent-config': 'high',
  'editor-data': 'high',
  'shell-history': 'high',
  'project-file': 'high',
  'shell-config': 'medium',
  env: 'medium',
  'credential-store': 'low',
};

const CHUNK_BYTES = 16 * 1024 * 1024;
const KEY_TAIL = 1024; // longer than any key, so a key is never split between chunks
const UTF16_MAX = 512 * 1024 * 1024;

// Shows only the provider's fixed prefix and the last 4 characters, the same
// amount provider consoles show. No random characters from the start of a key.

function mask(value) {
  const m = value.match(KNOWN_PREFIX);
  return `${m ? m[0] : ''}…${value.slice(-4)}`;
}

function fingerprint(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

function safeLstat(p) {
  try { return fs.lstatSync(p); } catch { return null; }
}

function safeStat(p) {
  try { return fs.statSync(p); } catch { return null; }
}

// lstat, but a symlink to a regular file is resolved. Symlinks to
// directories found while walking are never followed.
function fileStat(p) {
  const st = safeLstat(p);
  if (!st || !st.isSymbolicLink()) return st;
  const target = safeStat(p);
  return target && target.isFile() ? target : null;
}

// Small helper for config files such as .gitignore and .keyleakcheckignore.
function readSmallText(file) {
  const st = fileStat(file);
  if (!st || !st.isFile() || st.size === 0 || st.size > 1024 * 1024) return null;
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

function isKeyByte(b) {
  return (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 45 || b === 95;
}

function countNewlines(buf) {
  let n = 0;
  for (let i = buf.indexOf(10); i !== -1; i = buf.indexOf(10, i + 1)) n++;
  return n;
}

// UTF-16 (for example files written by Windows PowerShell 5.1) has a NUL byte
// next to every ASCII character, so it must be decoded before matching.
function utf16Kind(head) {
  if (head.length >= 2 && head[0] === 0xff && head[1] === 0xfe) return 'le';
  if (head.length >= 2 && head[0] === 0xfe && head[1] === 0xff) return 'be';
  const n = Math.min(head.length, 512) & ~1;
  if (n < 16) return null;
  let oddZero = 0;
  let evenZero = 0;
  for (let i = 0; i < n; i += 2) {
    if (head[i] === 0) evenZero++;
    if (head[i + 1] === 0) oddZero++;
  }
  const pairs = n / 2;
  if (oddZero > pairs * 0.4 && evenZero < pairs * 0.05) return 'le';
  if (evenZero > pairs * 0.4 && oddZero < pairs * 0.05) return 'be';
  return null;
}

// Reads a file of any size, read-only, and calls fn(text, firstLineNumber,
// isBinary) for each segment. Text is decoded as latin1: every byte maps to
// one character, so ASCII keys are matched in UTF-8 text, in other
// ASCII-compatible encodings and inside binary files (such as SQLite
// databases) alike. Segments are cut at a newline, or inside a very long line
// before any character that could belong to a key or its escape prefix, so
// a key is never split across two segments.
function readFile(file, size, chunkBytes, fn) {
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.allocUnsafe(Math.min(chunkBytes, Math.max(size, 1)));
    let pos = 0;
    let carry = Buffer.alloc(0);
    let line = 1;
    // Encoding and "binary" are decided from the file's first 8 KB, whatever
    // the chunk size, so the result never depends on how the file is read.
    const head = Buffer.alloc(Math.min(8192, size));
    if (head.length) fs.readSync(fd, head, 0, head.length, 0);
    const u16 = utf16Kind(head);
    if (u16) return { utf16: u16 };
    const binary = head.includes(0);
    for (;;) {
      const n = pos < size ? fs.readSync(fd, buf, 0, buf.length, pos) : 0;
      pos += n;
      const data = carry.length ? Buffer.concat([carry, buf.subarray(0, n)]) : Buffer.from(buf.subarray(0, n));
      const done = n === 0;
      let cut = data.length;
      if (!done) {
        const nl = data.lastIndexOf(10);
        if (nl >= 0) {
          cut = nl + 1;
        } else {
          const limit = Math.max(0, data.length - KEY_TAIL);
          cut = limit;
          while (cut > 0 && limit - cut < KEY_TAIL && isKeyByte(data[cut - 1])) cut--;
          // keep an escape prefix ("\", "\u", "%") together with the key after it
          while (cut > 0 && (data[cut - 1] === 92 || data[cut - 1] === 37)) cut--;
          // A run of key characters longer than KEY_TAIL cannot be one key on
          // its own; cutting inside it keeps memory bounded. (If the run starts
          // at the beginning of the buffer and is short, cut stays 0: nothing
          // is processed yet and the whole buffer waits for more data.)
          if (limit - cut >= KEY_TAIL) cut = limit;
        }
      }
      const segment = data.subarray(0, cut);
      carry = Buffer.from(data.subarray(cut));
      if (segment.length) {
        fn(segment.toString('latin1'), line, binary);
        line += countNewlines(segment);
      }
      if (done) return {};
    }
  } finally {
    fs.closeSync(fd);
  }
}

function readUtf16(file, kind, fn) {
  let buf = fs.readFileSync(file);
  if (kind === 'be') buf = Buffer.from(buf).swap16();
  let text = buf.toString('utf16le');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  fn(text, 1, false);
}

function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return starts;
}

function lineOf(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

// Walks a directory. Symlinked directories inside it are never followed (no
// loops, no escaping the scanned tree); symlinked files are read. Python
// virtual environments (folders with pyvenv.cfg) are skipped as third-party
// code. Folders that cannot be listed are recorded, never silently ignored.
function walk(dir, accept, opts, state, out = [], depth = 0) {
  if (depth > opts.maxDepth) return out;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    if (e && (e.code === 'EACCES' || e.code === 'EPERM')) state.unreadable.push(dir);
    return out;
  }
  for (const e of entries) {
    if (out.length >= opts.maxFiles) { state.truncated = true; break; }
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      if (e.name === 'cache' && path.basename(dir) === '.next') continue;
      if (fileStat(path.join(full, 'pyvenv.cfg'))) continue;
      walk(full, accept, opts, state, out, depth + 1);
    } else if ((e.isFile() || (e.isSymbolicLink() && fileStat(full))) && accept(e.name)) {
      out.push(full);
    }
  }
  return out;
}

// ---------- .gitignore ----------
// Approximates `git check-ignore` without running git: rules come from the
// global excludes file, .git/info/exclude and every .gitignore from the
// project root down to the file's folder. Later rules win, so negations work.
// Supports *, ?, **, leading "/" anchors, rules with a path, and folder rules
// ("secrets/"). If unsure, it reports "not covered" (the safer answer).

function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function parseRules(text, base) {
  const rules = [];
  for (let raw of text.split(/\r?\n/)) {
    raw = raw.replace(/\s+$/, '');
    if (!raw || raw.startsWith('#')) continue;
    let r = raw;
    const negate = r.startsWith('!');
    if (negate) r = r.slice(1);
    const dirOnly = r.endsWith('/');
    if (dirOnly) r = r.slice(0, -1);
    const anchored = r.includes('/');
    r = r.replace(/^\//, '');
    if (!r) continue;
    rules.push({ base, negate, dirOnly, anchored, re: globToRegex(r) });
  }
  return rules;
}

function globalExcludesFile(homeDir) {
  const cfg = readSmallText(path.join(homeDir, '.gitconfig'));
  const m = cfg && cfg.match(/^\s*excludesfile\s*=\s*(.+?)\s*$/im);
  if (m) return m[1].replace(/^~(?=\/|\\|$)/, homeDir).replace(/^"|"$/g, '');
  const xdg = process.env.XDG_CONFIG_HOME || path.join(homeDir, '.config');
  return path.join(xdg, 'git', 'ignore');
}

function gitRulesFor(fileDir, root, homeDir) {
  const rules = [];
  const g = readSmallText(globalExcludesFile(homeDir));
  if (g) rules.push(...parseRules(g, root));
  const info = readSmallText(path.join(root, '.git', 'info', 'exclude'));
  if (info) rules.push(...parseRules(info, root));
  const chain = [];
  for (let d = fileDir; ; d = path.dirname(d)) {
    chain.unshift(d);
    if (d === root || path.dirname(d) === d) break;
  }
  for (const d of chain) {
    const t = readSmallText(path.join(d, '.gitignore'));
    if (t) rules.push(...parseRules(t, d));
  }
  return rules;
}

function gitIgnored(file, root, homeDir) {
  let covered = false;
  for (const rule of gitRulesFor(path.dirname(file), root, homeDir)) {
    const rel = path.relative(rule.base, file);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) continue;
    const parts = rel.split(path.sep);
    let hit = false;
    for (let i = 1; i <= parts.length && !hit; i++) {
      const isDir = i < parts.length;
      if (rule.dirOnly && !isDir) continue;
      const candidate = rule.anchored ? parts.slice(0, i).join('/') : parts[i - 1];
      if (rule.re.test(candidate)) hit = true;
    }
    if (hit) covered = !rule.negate;
  }
  return covered;
}

// ---------- ignores and scope ----------

// Fingerprints listed in <project>/.keyleakcheckignore (one per line, "#" for
// comments) or passed with --ignore. Fingerprints are one-way hashes, so the
// ignore file is safe to commit.
function loadIgnores(root, extra = []) {
  const set = new Set(extra.map((s) => s.trim().toLowerCase()).filter(Boolean));
  const text = root ? readSmallText(path.join(root, '.keyleakcheckignore')) : null;
  if (text) {
    for (const line of text.split(/\r?\n/)) {
      const v = line.replace(/#.*/, '').trim().toLowerCase();
      if (/^[0-9a-f]{12}$/.test(v)) set.add(v);
    }
  }
  return set;
}

// Walking the home folder, the filesystem root, or any folder that contains
// the home folder as a "project" would read every file you own. The agent,
// MCP and shell locations in home are scanned separately anyway.
function isTooBroad(dir, homeDir) {
  const r = path.resolve(dir);
  const h = path.resolve(homeDir);
  const same = (a, b) => (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);
  if (same(r, h) || path.dirname(r) === r) return true;
  const rel = path.relative(r, h);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function buildTargets(opts) {
  const targets = [];
  const coverage = [];
  const state = { truncated: false, unreadable: [] };
  const walkOpts = { maxDepth: opts.maxDepth, maxFiles: opts.maxFiles };
  let projectSkipped = null;

  if (opts.home) {
    for (const loc of homeLocations(opts.homeDir, process.platform, opts.env)) {
      // A known location that is itself a symlink (dotfile managers) is
      // followed; symlinks found inside it are not.
      const st = safeStat(loc.path);
      const present = !!st && (loc.dir ? st.isDirectory() : st.isFile());
      coverage.push({ path: loc.path, tool: loc.tool, kind: loc.kind, present });
      if (!present) continue;
      if (loc.dir) {
        for (const f of walk(loc.path, (n) => HISTORY_FILE.test(n), walkOpts, state)) {
          targets.push({ file: f, kind: loc.kind, tool: loc.tool, locRoot: loc.path });
        }
      } else {
        targets.push({ file: loc.path, kind: loc.kind, tool: loc.tool, expectedFields: loc.expectedFields });
      }
    }
  }

  if (opts.project) {
    const root = path.resolve(opts.project);
    const st = safeStat(root);
    if (!opts.projectExplicit && isTooBroad(root, opts.homeDir)) {
      projectSkipped = root;
    } else if (st && st.isFile()) {
      coverage.push({ path: root, tool: 'file', kind: 'project-file', present: true });
      targets.push({ file: root, kind: projectKind(path.basename(root)), tool: 'project', root: path.dirname(root) });
    } else if (st && st.isDirectory()) {
      coverage.push({ path: root, tool: 'project', kind: 'project-file', present: true });
      for (const f of walk(root, (n) => PROJECT_FILE.test(n), walkOpts, state)) {
        targets.push({ file: f, kind: projectKind(path.basename(f)), tool: 'project', root });
      }
    } else {
      const err = new Error(`Path not found: ${root}`);
      err.code = 'ENOPATH';
      throw err;
    }
  }

  // De-duplicate files reached through more than one route (first one wins).
  const seen = new Set();
  return {
    coverage,
    projectSkipped,
    truncated: state.truncated,
    unreadable: state.unreadable,
    targets: targets.filter((t) => {
      const key = process.platform === 'win32' ? t.file.toLowerCase() : t.file;
      return seen.has(key) ? false : seen.add(key);
    }),
  };
}

function withDefaults(options) {
  const opts = {
    home: true,
    homeDir: os.homedir(),
    project: process.cwd(),
    projectExplicit: false,
    ignore: [],
    maxBytes: 2 * 1024 * 1024 * 1024,
    maxDepth: 12,
    maxFiles: 50000,
    chunkBytes: CHUNK_BYTES,
    env: process.env,
    ...options,
  };
  if (!opts.homeDir) opts.homeDir = os.homedir();
  return opts;
}

// Which locations would be scanned. Lists directories but reads no file contents.
function listLocations(options) {
  const { coverage, projectSkipped } = buildTargets(withDefaults(options));
  return { coverage, projectSkipped };
}

// Agents and editors embed Chromium browsers (for example Antigravity's
// browser profile inside ~/.gemini). Their caches hold API keys of websites
// the user visited; Google API keys in particular are public by design. A
// Chromium profile folder is recognised by the "Local State" file at its root.
const browserCache = new Map();
function inBrowserProfile(file, stopAt) {
  for (let d = path.dirname(file); d.length >= stopAt.length; d = path.dirname(d)) {
    if (!browserCache.has(d)) browserCache.set(d, !!fileStat(path.join(d, 'Local State')));
    if (browserCache.get(d)) return true;
    if (d === stopAt || path.dirname(d) === d) break;
  }
  return false;
}

const TEMP_AWS_MAX_HOURS = 36;

// Was this key stored on purpose, as the value of an expected JSON field?
function inExpectedField(text, index, fields) {
  if (!fields) return false;
  const before = text.slice(Math.max(0, index - 64), index);
  return fields.some((f) => new RegExp(`"${f}"\\s*:\\s*"$`).test(before));
}

function scan(options) {
  const opts = withDefaults(options);
  const { coverage, targets, projectSkipped, truncated, unreadable } = buildTargets(opts);
  const projectRoot = opts.project && !projectSkipped ? path.resolve(opts.project) : null;
  const ignoreRoot = projectRoot && safeStat(projectRoot) && safeStat(projectRoot).isFile() ? path.dirname(projectRoot) : projectRoot;
  const ignores = loadIgnores(ignoreRoot, opts.ignore);
  const keys = new Map();
  const skipped = unreadable.map((d) => ({ file: d, reason: 'folder-permission-denied' }));
  let filesRead = 0;
  let ignored = 0;

  for (const t of targets) {
    const st = fileStat(t.file);
    if (!st || !st.isFile() || st.size === 0) continue;
    if (st.size > opts.maxBytes) { skipped.push({ file: t.file, reason: 'too-large' }); continue; }

    let fileKind = t.kind;
    let fileSeverity = SEVERITY[t.kind] || 'high';
    let fileNote;
    if (t.kind === 'env' && t.tool === 'project' && !gitIgnored(t.file, t.root, opts.homeDir)) {
      fileNote = 'not covered by .gitignore';
      fileSeverity = 'high';
    }
    if (t.locRoot && inBrowserProfile(t.file, t.locRoot)) {
      fileKind = 'browser-data';
      fileSeverity = 'low';
    }
    const fileAgeHours = (Date.now() - st.mtimeMs) / 3.6e6;

    const record = (text, firstLine, binary) => {
      const found = findSecrets(text);
      if (!found.length) return;
      const starts = lineStarts(text);
      for (const s of found) {
        const fp = fingerprint(s.value);
        if (ignores.has(fp)) { ignored++; continue; }
        let severity = fileSeverity;
        let kind = fileKind;
        let keyNote = null;
        if (inExpectedField(text, s.index, t.expectedFields)) { severity = 'low'; kind = 'credential-store'; }
        if (s.pattern.id === 'aws-temporary') {
          if (fileAgeHours > TEMP_AWS_MAX_HOURS) {
            severity = 'low';
            keyNote = `expired: the file was last changed ${Math.floor(fileAgeHours / 24)} day(s) ago`;
          } else {
            keyNote = 'temporary credential, valid for up to 36 hours';
          }
        }
        if (!keys.has(fp)) {
          keys.set(fp, { fingerprint: fp, provider: s.pattern.provider, rule: s.pattern.id, masked: mask(s.value), severity, occurrences: [] });
        }
        const k = keys.get(fp);
        if (rank(severity) > rank(k.severity)) k.severity = severity;
        const note = [fileNote, keyNote, binary ? 'inside a binary or database file' : null].filter(Boolean).join('; ') || undefined;
        // Line numbers are meaningless inside binary files and databases.
        const line = binary ? null : firstLine + lineOf(starts, s.index) - 1;
        k.occurrences.push({ file: t.file, line, kind, tool: t.tool, note });
      }
    };

    try {
      const r = readFile(t.file, st.size, opts.chunkBytes, record);
      if (r.utf16) {
        if (st.size > UTF16_MAX) { skipped.push({ file: t.file, reason: 'too-large' }); continue; }
        readUtf16(t.file, r.utf16, record);
      }
    } catch (e) {
      skipped.push({ file: t.file, reason: e && (e.code === 'EACCES' || e.code === 'EPERM') ? 'permission-denied' : 'unreadable' });
      continue;
    }
    filesRead++;
  }

  const findings = [...keys.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || b.occurrences.length - a.occurrences.length);
  const complete = skipped.length === 0 && !truncated;
  return { findings, coverage, filesRead, skipped, truncated, projectSkipped, ignored, complete, grade: grade(findings) };
}

function rank(sev) {
  return { low: 1, medium: 2, high: 3 }[sev] || 0;
}

// Keys in their expected credential store ('low') do not affect the grade.
function grade(findings) {
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  if (high >= 3) return 'D';
  if (high >= 1) return 'C';
  if (medium >= 1) return 'B';
  return 'A';
}

module.exports = { scan, listLocations, mask, fingerprint, grade, gitIgnored, globToRegex };
