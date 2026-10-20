'use strict';

// Detection rules for AI-provider and adjacent credentials.
//
// A key may start right after a non-alphanumeric character, or right after an
// escape sequence: JSON/shell escapes ("\n", "\t"), JSON unicode escapes
// (""") and URL encoding ("%22"). Agent transcripts are JSONL, so a key
// pasted on its own line is stored as "...\nsk-proj-...". A plain \b would
// miss it, because "n" is a word character.
const START = String.raw`(?:(?<=\\[nrtfvb0]|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2})|(?<![A-Za-z0-9]))`;
const END = String.raw`(?![A-Za-z0-9])`;

// `anchors` are literals every match must contain; text without any of them
// is skipped before the (slower) regex runs.
const rule = (id, provider, anchors, body, end = END) => ({
  id, provider, anchors, re: new RegExp(START + body + end, 'g'),
});

// Order matters: specific prefixes come before the generic "sk-" rule so a
// single string is attributed to the most specific provider.
const PATTERNS = [
  rule('anthropic', 'Anthropic', ['sk-ant-'], String.raw`sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}`, ''),
  rule('anthropic-oauth', 'Anthropic (Claude login token)', ['sk-ant-'], String.raw`sk-ant-(?:oat|ort)\d{2}-[A-Za-z0-9_-]{40,}`, ''),
  rule('openrouter', 'OpenRouter', ['sk-or-'], String.raw`sk-or-v1-[a-f0-9]{64}`),
  rule('openai-project', 'OpenAI', ['sk-'], String.raw`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}`, ''),
  rule('openai-legacy', 'OpenAI', ['T3BlbkFJ'], String.raw`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
  rule('google', 'Google (Gemini / Cloud)', ['AIza'], String.raw`AIza[0-9A-Za-z_-]{35}`, String.raw`(?![0-9A-Za-z_-])`),
  rule('groq', 'Groq', ['gsk_'], String.raw`gsk_[A-Za-z0-9]{48,56}`),
  rule('xai', 'xAI', ['xai-'], String.raw`xai-[A-Za-z0-9]{60,100}`),
  rule('huggingface', 'Hugging Face', ['hf_'], String.raw`hf_[A-Za-z0-9]{30,40}`),
  rule('perplexity', 'Perplexity', ['pplx-'], String.raw`pplx-[A-Za-z0-9]{40,64}`),
  rule('replicate', 'Replicate', ['r8_'], String.raw`r8_[A-Za-z0-9]{37}`),
  rule('github', 'GitHub', ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'], String.raw`(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,90})`),
  rule('aws', 'AWS', ['AKIA'], String.raw`AKIA[0-9A-Z]{16}`),
  // ASIA keys are temporary (STS) credentials that expire within 36 hours.
  rule('aws-temporary', 'AWS (temporary credential)', ['ASIA'], String.raw`ASIA[0-9A-Z]{16}`),
  // Generic OpenAI-compatible keys (OpenAI legacy, DeepSeek and others).
  rule('openai-compatible', 'OpenAI-compatible (OpenAI, DeepSeek, ...)', ['sk-'], String.raw`sk-[A-Za-z0-9]{32,}`),
];

// The fixed, non-random start of each key type. Shared with the masking code.
const KNOWN_PREFIX = /^(?:sk-ant-[a-z]+\d{2}-|sk-or-v1-|sk-(?:proj|svcacct|admin)-|sk-|AIza|gsk_|xai-|hf_|pplx-|r8_|github_pat_|gh[pousr]_|AKIA|ASIA)/;

// Documentation placeholders read like words: "sk-proj-YOUR_API_KEY_HERE",
// "sk-your-key-goes-here". A value counts as one only if EVERY segment
// between "-" and "_" is a plain word (all lower case or all upper case
// letters, or a short number) AND at least one segment is a placeholder word.
// A random key almost never splits into whole-word segments, so a real key
// that happens to contain "dumMy" or "-my-" is kept (found by the randomised
// test). Runs like "xxxxxxxx" are caught by the entropy check below.
const PLACEHOLDER_WORD = /^(?:your|my|example|sample|placeholder|dummy|fake|changeme|redacted|insert|replace|here|goes|key|api|secret|token|test|xx+)$/i;

function readsLikeWords(body) {
  const segments = body.split(/[-_]+/).filter(Boolean);
  if (segments.length < 2) return segments.length === 1 && /^(?:your|example|placeholder|dummy|changeme|redacted)$/i.test(segments[0]);
  return segments.every((x) => /^[a-z]+$/.test(x) || /^[A-Z]+$/.test(x) || /^\d{1,4}$/.test(x))
    && segments.some((x) => PLACEHOLDER_WORD.test(x));
}

function shannonEntropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// Real keys are random strings; documentation samples ("sk-xxxxxxxx...",
// "sk-abababab...") are not. A random string of length L over an alphabet of
// size A has entropy close to log2(min(L, A)). The threshold is 60% of that,
// which rejects repetitive samples while keeping virtually every real key,
// including hex-only keys such as OpenRouter's (see the entropy test).
function alphabetSize(body) {
  if (/^[0-9a-f]+$/i.test(body)) return 16;
  if (/^[0-9A-Z]+$/.test(body)) return 36;
  return 64;
}

function isPlaceholder(value) {
  const body = value.replace(KNOWN_PREFIX, '');
  if (readsLikeWords(body)) return true;
  if (body.length < 8) return true;
  return shannonEntropy(body) < 0.6 * Math.log2(Math.min(body.length, alphabetSize(body)));
}

// Returns [{ index, value, pattern }] with overlapping matches resolved in
// favour of the earlier (more specific) rule.
function findSecrets(text) {
  const taken = [];
  const results = [];
  for (const pattern of PATTERNS) {
    if (!pattern.anchors.some((a) => text.includes(a))) continue;
    pattern.re.lastIndex = 0;
    let m;
    while ((m = pattern.re.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      if (taken.some(([s, e]) => start < e && end > s)) continue;
      if (isPlaceholder(m[0])) continue;
      taken.push([start, end]);
      results.push({ index: start, value: m[0], pattern });
    }
  }
  return results.sort((a, b) => a.index - b.index);
}

module.exports = { PATTERNS, KNOWN_PREFIX, findSecrets, isPlaceholder, shannonEntropy };
