'use strict';

// Builds a fake home and project with generated (non-real) keys, for the CI
// runtime-guarantee checks. Usage: node scripts/make-fixture.js <dir>
const path = require('path');
const { fakeKeys, write } = require('../test/helpers');

const dir = process.argv[2];
if (!dir) {
  process.stderr.write('usage: node scripts/make-fixture.js <dir>\n');
  process.exit(2);
}
const k = fakeKeys();
write(path.join(dir, 'home', '.claude', 'projects', 'demo', 'session.jsonl'), `${JSON.stringify({ content: `key:\n${k.openai}` })}\n`);
write(path.join(dir, 'home', '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { x: { env: { ANTHROPIC_API_KEY: k.anthropic } } } }));
write(path.join(dir, 'project', '.env'), `GEMINI_API_KEY=${k.google}\n`);
