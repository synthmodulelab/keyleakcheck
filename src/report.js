'use strict';

const os = require('os');
const { RECOVERY } = require('./providers');

function colors(enabled) {
  const wrap = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { bold: wrap(1), dim: wrap(2), red: wrap(31), yellow: wrap(33), green: wrap(32), cyan: wrap(36) };
}

// File names come from disk and may be hostile: a crafted name with terminal
// control sequences or bidirectional-override characters could rewrite or
// disguise the report. Replace them before printing.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
function clean(s) {
  return String(s).replace(UNSAFE, '?');
}

function tidy(p) {
  const home = os.homedir();
  return clean(p.startsWith(home) ? `~${p.slice(home.length)}` : p);
}

const KIND_LABEL = {
  'agent-data': 'agent data (history, logs, settings)',
  'agent-config': 'agent or MCP config',
  'editor-data': 'editor storage',
  'shell-history': 'shell history',
  'shell-config': 'shell startup file',
  'project-file': 'project file',
  env: '.env file',
  'credential-store': 'credential store (expected location)',
  'browser-data': 'browser cache',
};

const SKIP_REASON = {
  'too-large': 'larger than --max-file-mb',
  'permission-denied': 'permission denied',
  'folder-permission-denied': 'folder could not be listed: permission denied',
  unreadable: 'could not be read',
};

function gradeLabel(result) {
  return result.complete ? result.grade : `${result.grade} (partial scan)`;
}

function coverageWarnings(result, c) {
  const out = [];
  if (result.skipped.length) {
    out.push(c.yellow(`Warning: ${result.skipped.length} file(s) could not be scanned, so the result is incomplete:`));
    for (const s of result.skipped.slice(0, 5)) out.push(c.yellow(`   ${tidy(s.file)}  (${SKIP_REASON[s.reason] || s.reason})`));
    if (result.skipped.length > 5) out.push(c.yellow(`   …and ${result.skipped.length - 5} more (see --json)`));
  }
  if (result.truncated) {
    out.push(c.yellow('Warning: stopped after 50,000 files, so the result is incomplete. Point --path at a single project.'));
  }
  if (result.projectSkipped) {
    out.push(c.dim(`Note: ${tidy(result.projectSkipped)} is your home or root folder, so it was not walked as a project.`));
    out.push(c.dim('      Agent, MCP and shell files in your home were still checked. Use --path <project> to scan a project.'));
  }
  if (result.ignored) {
    out.push(c.dim(`Note: ${result.ignored} occurrence(s) ignored via .keyleakcheckignore or --ignore.`));
  }
  return out;
}

// One line per file: "path:12, 40, 41 (+3 more)", or "path (5 times)" for
// binary files, where line numbers carry no meaning.
function groupByFile(occurrences) {
  const groups = new Map();
  for (const o of occurrences) {
    if (!groups.has(o.file)) groups.set(o.file, { file: o.file, kind: o.kind, tool: o.tool, note: o.note, lines: [], count: 0 });
    const g = groups.get(o.file);
    g.count++;
    if (o.line != null) g.lines.push(o.line);
  }
  return [...groups.values()].map((g) => {
    let where = '';
    if (g.lines.length) {
      const shown = g.lines.slice(0, 3).join(', ');
      where = `:${shown}${g.lines.length > 3 ? ` (+${g.lines.length - 3} more)` : ''}`;
    } else if (g.count > 1) {
      where = ` (${g.count} times)`;
    }
    return { ...g, where };
  });
}

// Why a finding is low risk, in plain words.
function lowRiskAdvice(f) {
  const kinds = new Set(f.occurrences.map((o) => o.kind));
  if (f.rule === 'aws-temporary') {
    return 'Temporary AWS credentials expire within 36 hours, and this one has expired. Check that the long-term key or SSO login that issued it was not exposed too.';
  }
  if (kinds.has('browser-data') && kinds.size === 1) {
    return "Found only in a browser cache. Keys there usually belong to websites you visited and are public by design. If it is not in your own provider console, no action is needed.";
  }
  return 'This file is meant to hold a key. Keep it private (chmod 600) and out of backups and repos.';
}

function renderText(result, { color = false, version = '' } = {}) {
  const c = colors(color);
  const out = [];
  const sevColor = { high: c.red, medium: c.yellow, low: c.dim };
  out.push(c.bold(`Key Leak Check ${version}`) + c.dim('  (offline, read-only)'));
  out.push('');

  const present = result.coverage.filter((l) => l.present);
  out.push(`Scanned ${result.filesRead} files across ${present.length} locations.`);
  const warnings = coverageWarnings(result, c);

  if (!result.findings.length) {
    out.push('');
    if (result.complete) out.push(c.green('No AI provider keys found in plaintext. Grade: A'));
    else out.push(c.yellow(`No AI provider keys found in the files that were scanned. Grade: ${gradeLabel(result)}`));
    if (warnings.length) out.push('', ...warnings);
    out.push(c.dim('This is not a guarantee. Run with --list-locations to see what was covered.'));
    return out.join('\n');
  }

  const exposed = result.findings.filter((f) => f.severity !== 'low');
  const stored = result.findings.length - exposed.length;
  const totalOcc = exposed.reduce((n, f) => n + f.occurrences.length, 0);
  const storedNote = stored ? c.dim(` (+${stored} low-risk, listed below)`) : '';
  if (exposed.length) {
    out.push(`Found ${c.bold(exposed.length)} exposed key(s) in ${totalOcc} place(s)${storedNote}. Grade: ${c.bold(gradeLabel(result))}`);
  } else {
    out.push(`${c.green('No exposed keys.')} Grade: ${c.bold(gradeLabel(result))} ${c.dim(`(${stored} low-risk finding(s) listed below, for your information)`)}`);
  }
  if (warnings.length) out.push('', ...warnings);
  out.push('');

  result.findings.forEach((f, i) => {
    out.push(`${c.bold(`${i + 1}. ${f.provider}`)}  ${f.masked}  ${sevColor[f.severity](f.severity.toUpperCase())}  ${c.dim(`id ${f.fingerprint}`)}`);
    const byFile = groupByFile(f.occurrences);
    for (const g of byFile.slice(0, 5)) {
      const note = g.note ? c.yellow(` (${g.note})`) : '';
      out.push(`   ${tidy(g.file)}${g.where}  ${c.dim(`${KIND_LABEL[g.kind] || g.kind}, ${g.tool}`)}${note}`);
    }
    if (byFile.length > 5) out.push(c.dim(`   …and ${byFile.length - 5} more file(s)`));
    const r = RECOVERY[f.provider] || {};
    if (f.severity !== 'low') {
      const revoke = r.revoke || 'your provider console';
      out.push(`   ${c.cyan('Fix:')} 1) ${revoke.startsWith('http') ? 'revoke and replace: ' : ''}${revoke}`);
      out.push('        2) remove the old key from the files above (or run your agent\'s history cleanup)');
      if (r.limit || r.limitNote) out.push(`        3) cap spend on the new key: ${[r.limit, r.limitNote].filter(Boolean).join(' — ')}`);
    } else {
      out.push(`   ${c.dim(lowRiskAdvice(f))}`);
    }
    out.push('');
  });

  out.push(c.dim(`Keys are shown masked. Nothing was sent anywhere and no file was changed.`));
  out.push(c.dim(`Known test key? Add its id to .keyleakcheckignore in your project.`));
  return out.join('\n');
}

// JSON.stringify escapes C0 control characters but not C1 controls or
// bidirectional overrides, which can disguise text when the JSON is viewed.
// eslint-disable-next-line no-control-regex
const JSON_UNSAFE = /[\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

function renderJson(result, { version = '' } = {}) {
  return jsonSafe({
    tool: 'keyleakcheck',
    version,
    grade: result.grade,
    complete: result.complete,
    filesRead: result.filesRead,
    findings: result.findings,
    ignored: result.ignored,
    skipped: result.skipped,
    truncated: result.truncated,
    projectSkipped: result.projectSkipped,
    coverage: result.coverage,
  });
}

function jsonSafe(value) {
  return JSON.stringify(value, null, 2).replace(JSON_UNSAFE, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

// A shareable summary that contains no key material and no file paths.
function renderCard(result) {
  const exposed = result.findings.filter((f) => f.severity !== 'low');
  const high = exposed.filter((f) => f.severity === 'high').length;
  const providers = [...new Set(exposed.map((f) => f.provider.split(' ')[0]))];
  const W = 44;
  let list = providers.join(', ') || 'none';
  if (list.length > W - 16) list = `${list.slice(0, W - 17)}…`;
  const row = (s) => `│${`  ${s}`.padEnd(W)}│`;
  return [
    `┌${'─'.repeat(W)}┐`,
    row(`Key Leak Check  ·  Grade ${gradeLabel(result)}`),
    row(`Exposed keys: ${exposed.length} (${high} high risk)`),
    row(`Providers: ${list}`),
    row('Scanned offline. No keys shared.'),
    `└${'─'.repeat(W)}┘`,
  ].join('\n');
}

function renderLocations(result) {
  const lines = result.coverage.map((l) => `${l.present ? '✔' : '·'} ${tidy(l.path)}  (${l.tool}, ${KIND_LABEL[l.kind] || l.kind})`);
  if (result.projectSkipped) lines.push(`· ${tidy(result.projectSkipped)}  (home or root folder: not walked; use --path)`);
  return lines.join('\n');
}

module.exports = { renderText, renderJson, renderCard, renderLocations, clean };
