#!/usr/bin/env node
'use strict';
/**
 * Admin CLI for account-deletion requests.
 *   1) start the server with an admin token (min. 16 chars):
 *        Windows (cmd):   set ADMIN_TOKEN=some-long-secret-value && npm start
 *        macOS / Linux:   ADMIN_TOKEN=some-long-secret-value npm start
 *   2) in another terminal, with the same ADMIN_TOKEN set:
 *        node admin.js list                       - show all requests with what the account contains
 *        node admin.js approve U-2026-XXXXXX      - erase the account (reviews stay, shown as "Deleted user")
 *        node admin.js reject  U-2026-XXXXXX "reason"
 * Optional: BASE_URL (default http://localhost:3000)
 */
const BASE = process.env.BASE_URL || 'http://localhost:3000';
const TOKEN = process.env.ADMIN_TOKEN || '';
const [cmd, ref, ...rest] = process.argv.slice(2);
async function call(path, method, body) {
  const res = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', 'X-Admin-Token': TOKEN }, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await res.json(); } catch (e) { /* ignore */ }
  return { ok: res.ok, status: res.status, data };
}
(async () => {
  if (!TOKEN) { console.error('Set ADMIN_TOKEN (same value as on the server).'); process.exit(1); }
  if (cmd === 'list') {
    const r = await call('/api/admin/deletion-requests', 'GET');
    if (!r.ok) { console.error('Error', r.status, r.data); process.exit(1); }
    if (!r.data.requests.length) return console.log('No requests.');
    r.data.requests.forEach((x) => console.log(`${x.ref}  [${x.status}]  ${x.createdAt.slice(0, 10)}  ${x.name} <${x.email}>\n    jobs ${x.jobs}, services ${x.services}, reviews written ${x.reviewsWritten}, received ${x.reviewsReceived}, verified ${x.verified}, reports ${x.pendingReports}${x.reason ? `\n    reason: ${x.reason}` : ''}`));
  } else if ((cmd === 'approve' || cmd === 'reject') && ref) {
    const r = await call(`/api/admin/deletion-requests/${encodeURIComponent(ref)}/${cmd}`, 'POST', cmd === 'reject' ? { note: rest.join(' ') } : undefined);
    console.log(r.ok ? `${ref}: ${r.data.status}` : `Error ${r.status} ${JSON.stringify(r.data)}`);
  } else if (cmd === 'verifications') {
    const r = await call('/api/admin/verifications', 'GET');
    if (!r.ok) { console.error('Error', r.status, r.data); process.exit(1); }
    if (!r.data.requests.length) return console.log('No requests.');
    r.data.requests.forEach((x) => console.log(
      `${x.id}  [${x.status}]  ${x.createdAt.slice(0, 10)}  ${x.type}  ${x.name} <${x.email}>` +
      (x.business ? `\n    business: ${x.business.name}  NIP ${x.business.nip}${x.business.krs ? '  KRS ' + x.business.krs : ''}  (source: ${x.source || '?'}, repMatch: ${x.repMatch})` : '') +
      (x.position ? `\n    position: ${x.position}` : '')
    ));
  } else if ((cmd === 'verify-approve' || cmd === 'verify-reject') && ref) {
    const action = cmd === 'verify-approve' ? 'approve' : 'reject';
    const r = await call(`/api/admin/verifications/${encodeURIComponent(ref)}/${action}`, 'POST', action === 'reject' ? { note: rest.join(' ') } : undefined);
    console.log(r.ok ? `${ref}: ${r.data.status}` : `Error ${r.status} ${JSON.stringify(r.data)}`);
  } else {
    console.log('Usage: node admin.js list | approve <ref> | reject <ref> [reason]\n' +
      '       node admin.js verifications | verify-approve <id> | verify-reject <id> [reason]');
  }
})();
