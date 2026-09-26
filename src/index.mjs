export const TOOL_ID = 'rate-limit-header-inspector';
export const LIMITS = Object.freeze({ captureBytes: 1048576, policyBytes: 65536, depth: 16, responses: 1000, headers: 100, headerChars: 8192, delaySeconds: 604800, milliseconds: 5000 });
export const RULES = Object.freeze({ 'capture-invalid': 'warning', 'policy-invalid': 'warning', 'capture-incomplete': 'warning', 'no-evidence': 'warning', 'no-rate-limit-evidence': 'warning', 'response-invalid': 'warning', 'header-invalid': 'warning', 'limit-incomplete': 'warning', 'limit-inconsistent': 'warning', 'delay-inconsistent': 'warning', 'clock-skew-uncertain': 'warning', 'clock-unknown': 'warning', 'retry-unknown': 'warning', 'retry-budget-exceeded': 'error', 'limit-exceeded': 'warning', 'input-unreadable': 'warning', 'duplicate-key': 'warning' });
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const instant = x => {
  if (typeof x !== 'string') return null;
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,3})?Z$/.exec(x);
  if (!m) return null;
  const n = Date.parse(x);
  return Number.isFinite(n) && new Date(n).toISOString().startsWith(m[1]) ? n : null;
};
const httpDate = x => {
  if (typeof x !== 'string' || !/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(x)) return null;
  const n = Date.parse(x);
  return Number.isFinite(n) && new Date(n).toUTCString() === x ? n : null;
};
const whole = (x, min, max) => typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x) && Number.isSafeInteger(Number(x)) && Number(x) >= min && Number(x) <= max ? Number(x) : null;
function depth(value) {
  const stack = [[value, 0, new Set()]];
  while (stack.length) {
    const [x, n, ancestors] = stack.pop();
    if (n > LIMITS.depth) return n;
    if (x && typeof x === 'object') {
      if (ancestors.has(x)) return LIMITS.depth + 1;
      const next = new Set(ancestors); next.add(x);
      for (const child of Object.values(x)) stack.push([child, n + 1, next]);
    }
  }
  return 0;
}
export function validPolicy(p) { return obj(p) && Object.keys(p).every(k => ['schemaVersion', 'evaluationAt', 'maxRetrySeconds', 'maxClockSkewSeconds', 'safetySeconds'].includes(k)) && p.schemaVersion === '1' && instant(p.evaluationAt) !== null && Number.isSafeInteger(p.maxRetrySeconds) && p.maxRetrySeconds >= 1 && p.maxRetrySeconds <= LIMITS.delaySeconds && Number.isSafeInteger(p.maxClockSkewSeconds) && p.maxClockSkewSeconds >= 0 && p.maxClockSkewSeconds <= 3600 && Number.isSafeInteger(p.safetySeconds) && p.safetySeconds >= 0 && p.safetySeconds <= 300; }

export function inspectHeaders(capture, policy, { now = () => Date.parse(policy?.evaluationAt), budgetNow = Date.now, deadline = budgetNow() + LIMITS.milliseconds } = {}) {
  const findings = [], windows = [];
  const add = (ruleId, pointer, message, file = '@capture') => {
    if (!Object.hasOwn(RULES, ruleId)) throw new Error('unknown rule');
    findings.push({ ruleId, severity: RULES[ruleId], message, location: { file, pointer } });
  };
  const finish = checked => {
    findings.sort((a, b) => cmp(a.location.file, b.location.file) || cmp(a.location.pointer, b.location.pointer) || cmp(a.ruleId, b.ruleId));
    return { schemaVersion: '1', tool: TOOL_ID, status: findings.some(f => f.severity === 'warning') ? 'incomplete' : findings.length ? 'fail' : 'pass', summary: { checked, errors: findings.filter(f => f.severity === 'error').length, warnings: findings.filter(f => f.severity === 'warning').length }, findings, windows };
  };
  if (!validPolicy(policy)) { add('policy-invalid', '', 'Inspection policy is invalid', '@policy'); return finish(0); }
  const evaluationAt = now();
  if (!Number.isSafeInteger(evaluationAt)) { add('clock-unknown', '', 'Injected evaluation clock is invalid', '@policy'); return finish(0); }
  if (depth(capture) > LIMITS.depth) { add('limit-exceeded', '', 'JSON depth limit exceeded'); return finish(0); }
  if (!obj(capture) || capture.schemaVersion !== '1' || typeof capture.complete !== 'boolean' || !Array.isArray(capture.responses)) { add('capture-invalid', '', 'Captured response export is invalid'); return finish(0); }
  if (capture.responses.length > LIMITS.responses) { add('limit-exceeded', '/responses', 'Response record limit exceeded'); return finish(0); }
  if (!capture.responses.length) { add('no-evidence', '/responses', 'At least one captured response is required'); return finish(0); }
  if (!capture.complete) add('capture-incomplete', '/complete', 'Capture declares partial coverage');
  for (let i = 0; i < capture.responses.length; i++) {
    if (budgetNow() > deadline) { add('limit-exceeded', '', 'Evaluation time limit exceeded'); return finish(i); }
    const response = capture.responses[i], pointer = `/responses/${i}`;
    if (!obj(response) || !Number.isSafeInteger(response.status) || response.status < 100 || response.status > 599 || instant(response.capturedAt) === null || !obj(response.headers) || Object.keys(response.headers).length > LIMITS.headers) { add('response-invalid', pointer, 'Captured response record is invalid'); continue; }
    const capturedAt = instant(response.capturedAt);
    if (capturedAt > evaluationAt) { add('clock-unknown', pointer, 'Capture time is after evaluation clock'); continue; }
    const headers = new Map();
    let bad = false;
    for (const [name, value] of Object.entries(response.headers)) {
      if (!/^[A-Za-z0-9-]{1,100}$/.test(name) || typeof value !== 'string' || value.length > LIMITS.headerChars || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) { bad = true; break; }
      const lower = name.toLowerCase();
      if (headers.has(lower)) { bad = true; break; }
      headers.set(lower, value.trim());
    }
    if (bad) { add('header-invalid', `${pointer}/headers`, 'Header names or values are invalid or ambiguous'); continue; }
    const h = name => headers.get(name);
    if (!['retry-after', 'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset'].some(name => headers.has(name))) add('no-rate-limit-evidence', pointer, 'No rate-limit or retry header was captured');
    const date = h('date') === undefined ? null : httpDate(h('date'));
    if (h('date') !== undefined && date === null) add('header-invalid', `${pointer}/headers`, 'Server Date header is invalid');
    if (date !== null && Math.abs(date - capturedAt) > policy.maxClockSkewSeconds * 1000) add('clock-skew-uncertain', pointer, 'Server and capture clocks differ beyond policy');
    const limit = h('ratelimit-limit') === undefined ? null : whole(h('ratelimit-limit'), 1, 1000000000);
    const remaining = h('ratelimit-remaining') === undefined ? null : whole(h('ratelimit-remaining'), 0, 1000000000);
    if ((h('ratelimit-limit') !== undefined && limit === null) || (h('ratelimit-remaining') !== undefined && remaining === null)) add('header-invalid', `${pointer}/headers`, 'Rate limit count header is invalid');
    if ((limit === null) !== (remaining === null)) add('limit-incomplete', pointer, 'Rate limit count pair is incomplete');
    if (limit !== null && remaining !== null && (remaining > limit || (response.status === 429 && remaining > 0))) add('limit-inconsistent', pointer, 'Rate limit counts conflict with each other or response status');
    const candidates = [];
    const retry = h('retry-after');
    if (retry !== undefined) {
      const seconds = whole(retry, 0, LIMITS.delaySeconds);
      if (seconds !== null) candidates.push(Math.max(0, capturedAt + seconds * 1000 - evaluationAt));
      else {
        const dateValue = httpDate(retry);
        if (dateValue === null || dateValue - capturedAt > LIMITS.delaySeconds * 1000) add('header-invalid', `${pointer}/headers`, 'Retry-After header is invalid or exceeds delay limit');
        else {
          if (date === null) add('clock-unknown', pointer, 'HTTP-date retry lacks usable server Date evidence');
          candidates.push(Math.max(0, dateValue - evaluationAt, date === null ? 0 : capturedAt + (dateValue - date) - evaluationAt));
        }
      }
    }
    const reset = h('ratelimit-reset');
    if (reset !== undefined) {
      const seconds = whole(reset, 0, LIMITS.delaySeconds);
      if (seconds === null) add('header-invalid', `${pointer}/headers`, 'RateLimit-Reset delay is invalid');
      else candidates.push(Math.max(0, capturedAt + seconds * 1000 - evaluationAt));
    }
    if (candidates.length > 1 && Math.max(...candidates) - Math.min(...candidates) > 1000) add('delay-inconsistent', pointer, 'Retry hints disagree; longest wait retained');
    if (!candidates.length && (response.status === 429 || response.status === 503 || remaining === 0)) add('retry-unknown', pointer, 'No usable retry window was captured');
    const retrySeconds = candidates.length ? Math.ceil(Math.max(...candidates) / 1000) + policy.safetySeconds : 0;
    if (retrySeconds > policy.maxRetrySeconds) add('retry-budget-exceeded', pointer, 'Conservative retry wait exceeds policy budget');
    windows.push({ location: { file: '@capture', pointer }, status: response.status, retrySeconds });
  }
  return finish(capture.responses.length);
}
