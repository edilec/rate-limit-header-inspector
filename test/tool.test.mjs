import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectHeaders, TOOL_ID } from '../src/index.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy = { schemaVersion: '1', evaluationAt: '2026-01-01T00:00:30Z', maxRetrySeconds: 100, maxClockSkewSeconds: 30, safetySeconds: 0 };
const response = { status: 429, capturedAt: '2026-01-01T00:00:00Z', headers: { 'Date': 'Thu, 01 Jan 2026 00:00:00 GMT', 'Retry-After': '120', 'RateLimit-Limit': '100', 'RateLimit-Remaining': '0' } };
const capture = { schemaVersion: '1', complete: true, responses: [response] };

test('captured Retry-After seconds becomes a conservative remaining window', () => {
  const result = inspectHeaders(capture, policy);
  assert.equal(TOOL_ID, 'rate-limit-header-inspector');
  assert.equal(result.status, 'pass');
  assert.equal(result.windows[0].retrySeconds, 90);
  assert.equal(JSON.stringify(result).includes('Thu, 01 Jan'), false);
});

test('HTTP-date form uses server Date and injected evaluation clock', () => {
  const dated = { ...response, headers: { ...response.headers, 'Retry-After': 'Thu, 01 Jan 2026 00:02:00 GMT' } };
  const result = inspectHeaders({ ...capture, responses: [dated] }, policy, { now: () => Date.parse(policy.evaluationAt) });
  assert.equal(result.status, 'pass');
  assert.equal(result.windows[0].retrySeconds, 90);
});

test('inconsistent limits and material server clock skew are not clean', () => {
  const limits = { ...response, headers: { ...response.headers, 'RateLimit-Remaining': '101' } };
  assert.equal(inspectHeaders({ ...capture, responses: [limits] }, policy).status, 'incomplete');
  const skew = { ...response, headers: { ...response.headers, 'Date': 'Thu, 01 Jan 2026 00:05:00 GMT', 'Retry-After': 'Thu, 01 Jan 2026 00:06:00 GMT' } };
  const result = inspectHeaders({ ...capture, responses: [skew] }, policy);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.windows[0].retrySeconds, 330);
});

test('policy retry budget is a failure, not a live retry', () => {
  const result = inspectHeaders(capture, { ...policy, maxRetrySeconds: 60 });
  assert.equal(result.status, 'fail');
  assert.equal(result.findings[0].ruleId, 'retry-budget-exceeded');
});

test('header name casing conflicts and control bytes remain ambiguous', () => {
  const duplicate = { ...response, headers: { ...response.headers, 'retry-after': '30' } };
  assert.equal(inspectHeaders({ ...capture, responses: [duplicate] }, policy).status, 'incomplete');
  const control = { ...response, headers: { ...response.headers, 'Retry-After': '\r120' } };
  assert.equal(inspectHeaders({ ...capture, responses: [control] }, policy).status, 'incomplete');
});

test('response without any relevant rate-limit or retry header is not a clean check', () => {
  const empty = { ...response, status: 200, headers: {} };
  const result = inspectHeaders({ ...capture, responses: [empty] }, policy);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.findings[0].ruleId, 'no-rate-limit-evidence');
});

test('record, header, value, depth and injected deadline N/N+1', () => {
  const many = n => ({ ...capture, responses: Array.from({ length: n }, () => response) });
  assert.equal(inspectHeaders(many(1000), policy).status, 'pass');
  assert.equal(inspectHeaders(many(1001), policy).status, 'incomplete');
  const headers = n => ({ ...response, status: 200, headers: { 'RateLimit-Limit': '100', 'RateLimit-Remaining': '50', ...Object.fromEntries(Array.from({ length: n - 2 }, (_, i) => [`X-${i}`, 'v'])) } });
  assert.equal(inspectHeaders({ ...capture, responses: [headers(100)] }, policy).status, 'pass');
  assert.equal(inspectHeaders({ ...capture, responses: [headers(101)] }, policy).status, 'incomplete');
  const val = n => ({ ...response, headers: { ...response.headers, 'X-Note': 'v'.repeat(n) } });
  assert.equal(inspectHeaders({ ...capture, responses: [val(8192)] }, policy).status, 'pass');
  assert.equal(inspectHeaders({ ...capture, responses: [val(8193)] }, policy).status, 'incomplete');
  const nested = n => { const d = structuredClone(capture); let x = d; for (let i = 0; i < n; i++) { x.extra = {}; x = x.extra; } return d; };
  assert.equal(inspectHeaders(nested(16), policy).status, 'pass');
  assert.equal(inspectHeaders(nested(17), policy).status, 'incomplete');
  assert.equal(inspectHeaders(capture, policy, { budgetNow: () => 5000, deadline: 5000 }).status, 'pass');
  assert.equal(inspectHeaders(capture, policy, { budgetNow: () => 5001, deadline: 5000 }).status, 'incomplete');
});

test('CLI separates invalid config from unreadable capture and confines symlinks', () => {
  const root = mkdtempSync(join(tmpdir(), 'rate-test-'));
  writeFileSync(join(root, 'policy.json'), JSON.stringify(policy));
  const run = (...args) => spawnSync(process.execPath, ['bin/rate-limit-header-inspector.mjs', '--root', root, ...args], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  const bad = run('--policy', 'policy.json', '--unknown', 'x');
  assert.equal(bad.status, 2); assert.equal(bad.stdout, '');
  const missing = run('--policy', 'policy.json', '--capture', 'missing.json');
  assert.equal(missing.status, 2); assert.equal(JSON.parse(missing.stdout).status, 'incomplete');
  const outside = mkdtempSync(join(tmpdir(), 'rate-out-'));
  writeFileSync(join(outside, 'capture.json'), JSON.stringify(capture));
  symlinkSync(join(outside, 'capture.json'), join(root, 'link.json'));
  const escape = run('--policy', 'policy.json', '--capture', 'link.json');
  assert.equal(escape.status, 2); assert.equal(escape.stdout, '');
});

test('RateLimit-Reset and conflicting retry hints retain the longer wait', () => {
  const reset = { ...response, headers: { ...response.headers, 'Retry-After': '30', 'RateLimit-Reset': '60' } };
  const result = inspectHeaders({ ...capture, responses: [reset] }, policy);
  assert.equal(result.status, 'incomplete');
  assert.equal(result.windows[0].retrySeconds, 30);
  assert.ok(result.findings.some(f => f.ruleId === 'delay-inconsistent'));
  const noServerDate = { ...response, headers: { 'Retry-After': 'Thu, 01 Jan 2026 00:02:00 GMT' } };
  assert.equal(inspectHeaders({ ...capture, responses: [noServerDate] }, policy).status, 'incomplete');
});

test('capture byte N/N+1, strict UTF-8 and escaped duplicate completeness keys', () => {
  const root = mkdtempSync(join(tmpdir(), 'rate-bytes-'));
  writeFileSync(join(root, 'policy.json'), JSON.stringify(policy));
  const plain = JSON.stringify(capture);
  const run = () => spawnSync(process.execPath, ['bin/rate-limit-header-inspector.mjs', '--root', root, '--policy', 'policy.json', '--capture', 'capture.json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  writeFileSync(join(root, 'capture.json'), plain + ' '.repeat(1048576 - Buffer.byteLength(plain)));
  assert.equal(run().status, 0);
  writeFileSync(join(root, 'capture.json'), plain + ' '.repeat(1048577 - Buffer.byteLength(plain)));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'limit-exceeded');
  writeFileSync(join(root, 'capture.json'), Buffer.from([0xff]));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'input-unreadable');
  writeFileSync(join(root, 'capture.json'), plain.replace('"complete":true', '"com\\u0070lete":false,"complete":true'));
  assert.equal(JSON.parse(run().stdout).findings[0].ruleId, 'duplicate-key');
});

test('policy byte N/N+1 and duplicate keys are invalid configuration', () => {
  const root = mkdtempSync(join(tmpdir(), 'rate-policy-bytes-'));
  const plain = JSON.stringify(policy);
  writeFileSync(join(root, 'capture.json'), JSON.stringify(capture));
  const run = () => spawnSync(process.execPath, ['bin/rate-limit-header-inspector.mjs', '--root', root, '--policy', 'policy.json', '--capture', 'capture.json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
  writeFileSync(join(root, 'policy.json'), plain + ' '.repeat(65536 - Buffer.byteLength(plain)));
  assert.equal(run().status, 0);
  writeFileSync(join(root, 'policy.json'), plain + ' '.repeat(65537 - Buffer.byteLength(plain)));
  const over = run(); assert.equal(over.status, 2); assert.equal(over.stdout, '');
  writeFileSync(join(root, 'policy.json'), plain.replace('"schemaVersion":"1"', '"schemaVersion":"0","schemaVersion":"1"'));
  const duplicate = run(); assert.equal(duplicate.status, 2); assert.equal(duplicate.stdout, '');
});
