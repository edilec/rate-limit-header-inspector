# Rate Limit Header Inspector

`TOOL_ID=rate-limit-header-inspector`. A zero-dependency Node 22+ offline reporter for captured HTTP response headers. It does not send requests, sleep, schedule jobs or retry traffic. It calculates a conservative local retry window from exported evidence and an explicit evaluation clock; this is not a promise that a server will accept a retry.

```sh
node bin/rate-limit-header-inspector.mjs --root examples/passing --policy policy.json --capture capture.json
node bin/rate-limit-header-inspector.mjs --root examples/failing --policy policy.json --capture capture.json
```

The first example exits 0 with 90 seconds remaining. The second exits 1 because that window exceeds a 60-second policy budget. `@capture` and `@policy` are logical source roles; `/responses/N` is a zero-based pointer into the exact captured file named at invocation. No response header value, path or request identifier is emitted.

## Export and timing contract

Policy: `{"schemaVersion":"1","evaluationAt":"2026-01-01T00:00:30Z","maxRetrySeconds":100,"maxClockSkewSeconds":30,"safetySeconds":0}`. The evaluation time is required; there is no implicit live retry clock. The library accepts an injected `now()` epoch-millisecond callback that overrides `evaluationAt` for controlled use. A separate injected `budgetNow()` drives only its 5-second evaluation limit.

Capture: `{"schemaVersion":"1","complete":true,"responses":[{"status":429,"capturedAt":"2026-01-01T00:00:00Z","headers":{"Date":"Thu, 01 Jan 2026 00:00:00 GMT","Retry-After":"120","RateLimit-Limit":"100","RateLimit-Remaining":"0"}}]}`. `complete:true` and at least one response are required for pass. Captured times use explicit UTC `Z` and may have 1–3 fractional digits. Header names are case-insensitive; duplicate spellings under case folding are ambiguous. Values with control bytes are rejected. `Date` and HTTP-date `Retry-After` use the exact IMF-fixdate form. Numeric `Retry-After` and `RateLimit-Reset` are nonnegative delta-seconds (maximum 604,800); the latter is not interpreted as a Unix timestamp. Limit and remaining are nonnegative integer counts, with limit at least one.

For seconds and reset hints, the deadline is `capturedAt + delta`. For an HTTP-date hint, the auditor computes both the absolute date deadline and the local captured-time deadline implied by the server `Date`, then retains the later one. It subtracts the injected evaluation time, floors negative waits at zero, takes the longest captured hint, rounds up to whole seconds and adds `safetySeconds`. If hints differ by more than one second, or `Date` differs from `capturedAt` beyond `maxClockSkewSeconds`, the report is incomplete while retaining the conservative window. An HTTP-date hint without usable server `Date` is likewise incomplete. A 429/503 response, or zero remaining count, with no usable retry hint is incomplete. A computed wait above `maxRetrySeconds` is a policy failure, never an attempted retry.

## Rules and exits

| Rule | Severity | Meaning |
| --- | --- | --- |
| `retry-budget-exceeded` | error | Conservative wait exceeds policy maximum. |
| `capture-invalid`, `policy-invalid`, `response-invalid`, `header-invalid` | warning | Evidence or configuration shape unusable. |
| `capture-incomplete`, `no-evidence`, `no-rate-limit-evidence`, `limit-incomplete`, `limit-inconsistent` | warning | Partial/vacuous or contradictory limit evidence. |
| `delay-inconsistent`, `clock-skew-uncertain`, `clock-unknown`, `retry-unknown` | warning | Retry timing cannot be certified cleanly. |
| `limit-exceeded`, `input-unreadable`, `duplicate-key` | warning | Bound, read or JSON ambiguity. |

Warnings make status `incomplete` and exit 2 even if the budget was exceeded. Otherwise a budget error makes `fail` and exit 1; complete consistent evidence within budget makes `pass` and exit 0. Invalid CLI arguments, root, escaped/symlinked paths or invalid/duplicate-key policy exit 2 with empty stdout and fixed stderr. An unreadable, undecodable, unparseable, oversized or duplicate-key capture emits an incomplete JSON report on stdout. JSON keys are compared after escape decoding. Stdout is one deterministic report; findings sort by code-unit `(source role, pointer, rule)` and never echo untrusted headers.

## Limits and non-goals

Capture 1,048,576 bytes; policy 65,536 bytes; JSON depth 16; 1,000 responses; 100 headers per response; 8,192 characters per header value; retry delta 604,800 seconds; evaluation 5,000 ms. Limits are inclusive; N+1 is incomplete for capture evidence or invalid configuration for policy. Input is strict UTF-8 and realpath-confined inside `--root`. The tool writes no files and uses no network. No live retries, status polling, automatic throttling, generic vendor-specific `X-RateLimit-*` interpretation, or inference of future server behavior is included. The library exports `TOOL_ID`, `LIMITS`, `RULES`, `validPolicy` and `inspectHeaders(capture,policy,{now,budgetNow,deadline})`.

Run `npm run check` for syntax and behavioral tests.
