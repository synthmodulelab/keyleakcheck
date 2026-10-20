'use strict';

// Where to revoke a key and how to cap spend. Links are printed, never opened.
// Each URL was checked against the provider's documentation (October 2026);
// where no stable limit URL is documented, a plain instruction is given.
// Consoles change: if a link is stale, please open an issue.
const RECOVERY = {
  Anthropic: {
    revoke: 'https://platform.claude.com/settings/keys',
    limitNote: 'Set a spend limit for the workspace in the Claude Console settings.',
  },
  'Anthropic (Claude login token)': {
    revoke: 'Sign out of Claude Code (/logout) and sign in again to replace this token.',
  },
  OpenAI: {
    revoke: 'https://platform.openai.com/api-keys',
    limit: 'https://platform.openai.com/settings/organization/limits',
    limitNote: 'Turn on "Enforce a hard limit" so requests stop at the cap.',
  },
  'OpenAI-compatible (OpenAI, DeepSeek, ...)': {
    revoke: 'Revoke it in the console of the provider that issued it (OpenAI: https://platform.openai.com/api-keys, DeepSeek: https://platform.deepseek.com/api_keys)',
  },
  'Google (Gemini / Cloud)': {
    revoke: 'https://aistudio.google.com/apikey',
    limitNote: 'Add API key restrictions, and a budget alert in Google Cloud Billing (budgets alert; they do not stop spend).',
  },
  OpenRouter: {
    revoke: 'https://openrouter.ai/settings/keys',
    limitNote: 'Set a credit limit on the replacement key.',
  },
  Groq: { revoke: 'https://console.groq.com/keys' },
  xAI: { revoke: 'https://console.x.ai' },
  'Hugging Face': { revoke: 'https://huggingface.co/settings/tokens' },
  Perplexity: { revoke: 'https://www.perplexity.ai/settings/api' },
  Replicate: { revoke: 'https://replicate.com/account/api-tokens' },
  GitHub: { revoke: 'https://github.com/settings/tokens' },
  AWS: { revoke: 'https://console.aws.amazon.com/iam/home#/security_credentials' },
  'AWS (temporary credential)': {
    revoke: "Temporary credentials expire on their own within 36 hours. To end them now, revoke the role's active sessions in IAM. Also check that the long-term key or SSO login that issued them was not exposed.",
  },
};

module.exports = { RECOVERY };
