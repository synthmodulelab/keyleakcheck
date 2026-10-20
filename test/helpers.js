'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// Fake keys are assembled at runtime so this repository never contains a
// string that looks like a real credential (and never trips push protection).
function rand(n, alphabet) {
  const bytes = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
}
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';

function fakeKeys() {
  return {
    anthropic: ['sk', 'ant', 'api03', rand(93, ALNUM) + 'AA'].join('-'),
    openai: ['sk', 'proj', rand(120, ALNUM)].join('-'),
    google: 'AI' + 'za' + rand(35, ALNUM),
    openrouter: ['sk', 'or', 'v1', rand(64, HEX)].join('-'),
    oauth: ['sk', 'ant', 'oat01', rand(93, ALNUM) + 'AA'].join('-'),
  };
}

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

module.exports = { fakeKeys, tmpdir, write };
