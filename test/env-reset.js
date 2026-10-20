'use strict';
// Tests point HOME at temporary folders. Make sure variables that relocate
// agent folders on the developer's own machine cannot redirect a test there.
for (const v of ['CLAUDE_CONFIG_DIR', 'CODEX_HOME', 'XDG_CONFIG_HOME']) delete process.env[v];
