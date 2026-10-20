#!/usr/bin/env node
'use strict';

// Network tripwire: this tool never needs the network. If any code path ever
// tries to use fetch, fail loudly instead of sending data.
globalThis.fetch = () => {
  throw new Error('keyleakcheck: network access is disabled by design');
};

// Piping into `head` or closing the terminal early is normal; exit quietly.
process.stdout.on('error', (e) => {
  if (e && e.code === 'EPIPE') process.exit(process.exitCode || 0);
  throw e;
});

const path = require('path');
const { scan, listLocations } = require('../src/scan');
const { renderText, renderJson, renderCard, renderLocations } = require('../src/report');
const { version } = require('../package.json');

const HELP = `keyleakcheck ${version}
Find AI provider API keys that coding agents, MCP clients and shells left in
plaintext on this machine. Runs offline and read-only.

Usage: npx keyleakcheck [options]

Options:
  --path <dir|file>   Project directory (or a single file) to scan (default:
                      current directory; skipped automatically if that is your
                      home or root folder)
  --no-project        Skip the project directory
  --no-home           Skip agent, MCP and shell files in your home directory
                      (recommended for CI and pre-commit hooks)
  --ignore <id>       Ignore a finding by its id (repeatable). Ids can also be
                      listed in <project>/.keyleakcheckignore
  --json              Machine-readable output (keys masked)
  --card              Print a shareable score card (no keys, no paths)
  --list-locations    Show which locations are checked, without reading them
  --max-file-mb <n>   Skip files larger than n MB (default: 2048)
  -v, --version       Print version
  -h, --help          Print this help

Exit codes:
  0  no high-risk keys found
  1  high-risk keys found
  2  error
  3  no high-risk keys found, but some files could not be scanned
`;

function parse(argv) {
  const o = { home: true, project: process.cwd(), projectExplicit: false, ignore: [], format: 'text', list: false, maxBytes: 2048 * 1024 * 1024 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--path') {
      const v = argv[++i];
      if (!v) throw new Error('--path needs a directory');
      o.project = path.resolve(v);
      o.projectExplicit = true;
    } else if (a === '--ignore') {
      const v = argv[++i];
      if (!v || !/^[0-9a-fA-F]{12}$/.test(v)) throw new Error('--ignore needs a 12-character finding id');
      o.ignore.push(v);
    } else if (a === '--no-project') o.project = null;
    else if (a === '--no-home') o.home = false;
    else if (a === '--json') o.format = 'json';
    else if (a === '--card') o.format = 'card';
    else if (a === '--list-locations') o.list = true;
    else if (a === '--max-file-mb') {
      const n = Number(argv[++i]);
      if (!(n > 0)) throw new Error('--max-file-mb needs a positive number');
      o.maxBytes = n * 1024 * 1024;
    } else if (a === '-v' || a === '--version') o.format = 'version';
    else if (a === '-h' || a === '--help') o.format = 'help';
    else throw new Error(`Unknown option: ${a}`);
  }
  return o;
}

function main() {
  let o;
  try {
    o = parse(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${HELP}`);
    return 2;
  }
  if (o.format === 'help') { process.stdout.write(HELP); return 0; }
  if (o.format === 'version') { process.stdout.write(`${version}\n`); return 0; }

  const scanOptions = { home: o.home, project: o.project, projectExplicit: o.projectExplicit, ignore: o.ignore, maxBytes: o.maxBytes };

  if (o.list) {
    process.stdout.write(`${renderLocations(listLocations(scanOptions))}\n`);
    return 0;
  }
  const result = scan(scanOptions);
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const text = o.format === 'json' ? renderJson(result, { version })
    : o.format === 'card' ? renderCard(result)
      : renderText(result, { color, version });
  process.stdout.write(`${text}\n`);
  if (result.findings.some((f) => f.severity === 'high')) return 1;
  return result.complete ? 0 : 3;
}

try {
  process.exitCode = main();
} catch (e) {
  process.stderr.write(`keyleakcheck: ${e.message}\n`);
  process.exitCode = 2;
}
