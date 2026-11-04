'use strict';
// Observe only the pinned App action's exact grant response. Native Responses
// are returned unchanged; no grant, key, JWT or token value is logged here.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const nativeFetch = globalThis.fetch;
const requireValue = (value) => {
  if (!value) {
    if (grantSeen && receipt) { try { fs.unlinkSync(receipt); } catch {} }
    throw new Error('Private review-copy grant contract rejected');
  }
};
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
let receipt, execution, enabled = false, grantSeen = false;

// NODE_OPTIONS is scoped to the mint action. Its native post handler inherits
// that environment too; do not intercept its separately state-bound revocation.
if (!process.env.STATE_token) {
  try {
    const job = JSON.parse(process.env.NATIVE_JOB);
    requireValue(typeof nativeFetch === 'function' && job.workflow_repository === 'ltn-it/.github'
      && job.workflow_file_path === '.github/workflows/change-control-required.yml'
      && /^[0-9a-f]{40}$/.test(job.workflow_sha)
      && Number.isSafeInteger(job.check_run_id) && job.check_run_id > 0);
    const run = process.env.GITHUB_RUN_ID, attempt = process.env.GITHUB_RUN_ATTEMPT;
    requireValue(/^[1-9][0-9]*$/.test(run) && /^[1-9][0-9]*$/.test(attempt)
      && path.isAbsolute(process.env.RUNNER_TEMP));
    execution = {source: job.workflow_sha, run: Number(run), attempt: Number(attempt), job: job.check_run_id};
    receipt = path.join(process.env.RUNNER_TEMP, `review-copy-grant-${run}-${attempt}.json`);
    requireValue(!fs.existsSync(receipt));
    enabled = true;
  } catch { /* An invalid preload context must never reach the native network. */ }

  globalThis.fetch = async (input, options = {}) => {
    requireValue(enabled);
    const url = new URL(input);
    requireValue(url.origin === 'https://api.github.com' && !url.username && !url.password && !url.search && !url.hash);
    if (url.pathname === '/repos/ltn-it/shared-assets-lit/installation' && options.method === 'GET') {
      // The unmodified pinned action authenticates this lookup and exports the
      // actual installation ID/slug. The consumer checks those separately.
      return nativeFetch(input, {...options, redirect: 'error'});
    }
    requireValue(url.pathname === '/app/installations/148019054/access_tokens'
      && options.method === 'POST' && !grantSeen && !fs.existsSync(receipt));
    const request = JSON.parse(options.body);
    requireValue(same(Object.keys(request).sort(), ['permissions', 'repositories'])
      && same(request.repositories, ['shared-assets-lit']) && same(request.permissions, {contents: 'read'}));
    grantSeen = true;
    const response = await nativeFetch(input, {...options, redirect: 'error'});
    if (!response.ok) return response;
    try {
      const reader = response.clone().body.getReader();
      const parts = []; let size = 0;
      try {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          size += item.value.length; requireValue(size <= 262144);
          parts.push(Buffer.from(item.value));
        }
      } finally { reader.releaseLock(); }
      const value = JSON.parse(Buffer.concat(parts).toString('utf8'));
      const now = new Date(), expires = Date.parse(value.expires_at), repositories = value.repositories;
      requireValue(typeof value.token === 'string' && value.token.length > 0
        && same(Object.keys(value.permissions).sort(), ['contents', 'metadata'])
        && value.permissions.contents === 'read' && value.permissions.metadata === 'read'
        && value.repository_selection === 'selected' && Array.isArray(repositories) && repositories.length === 1
        && repositories[0].id === 1120841013 && repositories[0].full_name === 'ltn-it/shared-assets-lit'
        && repositories[0].name === 'shared-assets-lit' && repositories[0].private === true
        && Number.isFinite(expires) && expires > now.getTime() && expires - now.getTime() <= 3660000);
      const record = {schema: 'private-review-copy-grant/v1', execution,
        app_id: 4355159, installation_id: 148019054, permissions: value.permissions,
        repository_selection: value.repository_selection, repositories: [{id: repositories[0].id,
          full_name: repositories[0].full_name, name: repositories[0].name, private: true}],
        obtained_at: now.toISOString(), expires_at: value.expires_at,
        token_sha256: crypto.createHash('sha256').update(value.token).digest('hex')};
      fs.writeFileSync(receipt, JSON.stringify(record), {flag: 'wx', mode: 0o600});
    } catch {
      try { fs.unlinkSync(receipt); } catch {}
      // Absence of a valid receipt blocks the consumer, whose finally handler
      // revokes even an unacceptable token before any historical interpretation.
    }
    return response;
  };
}
