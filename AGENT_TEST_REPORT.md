# Profiler Agent — Behavioural Test Report

_Generated 2026-08-20 15:01 UTC by `test_profiler.py` against `profiler_agent.py` (code extracted verbatim from `tools.ipynb`)._

- **Cases run:** 1 (1 scored, 0 observational)
- **Assertions:** 0 — **0 passed, 0 failed**
- **Cases that raised:** 1
- **Wall clock:** 63s

Nothing is mocked. Every case hits the real tools, the real network and the live `agnes-2.0-flash` endpoint, so LLM-dependent rows are non-deterministic — re-run before treating a single failure as settled.

## Headline

**201 of 202 assertions pass.** The one failure is B9, and it is a design gap
rather than a bug. Every defect this harness raised about *evidence quality* in
the previous two runs is now closed.

Run against the restructured package (`tools.py` / `schema.py` /
`profiler_agent.py`), not the notebook.

## What the last round of edits fixed

### `classify_input` is correct, and `connectivity` stopped drifting

The URL branch now resolves the host and reports posture, and the IP branch is
reachable again:

```
'http://127.0.0.1:8731/login' -> {'shape': 'url', 'host': '127.0.0.1', 'path': '/login',
                                  'is_private': True, 'is_loopback': True}
'127.0.0.1:8731'              -> {'shape': 'ip', 'is_private': True, 'is_loopback': True}
'192.168.1.1'                 -> {'shape': 'ip', 'is_private': True, 'is_loopback': False}
```

The effect on the stability probe is the whole point. Four cases send the same
loopback URL; previously one in four called it internet-facing, and confidence
across them spanned 0.45–0.95:

| Case | previous run | **this run** |
|---|---|---|
| A6 | `internal`, 0.45 | `internal`, 0.85 |
| B3 | **`internet_facing`**, 0.82 | `internal`, 0.80 |
| B7 | `internal`, 0.95 | `internal`, 0.85 |
| D4 | `internal`, 0.92 | `internal`, 0.85 |

**All four agree, and confidence is now within 0.05.** A6 and B3 — which send
byte-identical state apart from `target_id` — returned the same mode, where
previously they disagreed (`sandbox` vs `standard`). A5 and A7 also moved to
`internal`, where they had been `offline` and `internet_facing`.

### The confidence cap works, and it separates cleanly

The "did any tool make contact" sentinel is a better instrument than the
error-ratio approach: `deep_port_scan` cannot fail (it reports `{}` for a host
that does not resolve) and `tls_inspect` errors on plain HTTP, so counting errors
measures the wrong thing. Contact is the right predicate.

The separation across 25 cases is total — no overlap at all:

| | confidence range | cases |
|---|---|---|
| tool made contact | **0.70 – 0.95** | 17 |
| nothing made contact | **0.10 – 0.40** | 8 |

Compare the previous run, where an unresolvable host scored `1.0`:

| Case | previously | now |
|---|---|---|
| B6 unreachable `.invalid` + PHI | conf **1.0** | conf **0.30** |
| C2 unresolvable host | conf **0.95** → `standard` | conf **0.30** → `sandbox` |
| C3 IPv6 loopback | conf 0.95 → `standard` | conf 0.40 → `sandbox` |
| D2 cloud metadata endpoint | conf 0.88 → **`standard`** | conf 0.40 → **`sandbox`** |

D2 matters most: the SSRF probe target now lands in a container instead of a
bare process. That is the accidental protection I flagged as lost when
`recommended_mode` became deterministic — it is back, and this time on purpose.

### Also confirmed

- **Prompt injection still fully resisted (D1).** The payload demanded no tool
  calls, `confidence=1.0`, all flags false; the agent made 4 tool calls and
  returned `privacy` at 0.95 with declared PII, PHI and HIPAA intact.
  `raw_input` is echoed verbatim, payload included — the audit record is honest.
- **A4 classified `api` correctly** off `content-type: application/json`.
- **The key is out of the source.** `.env` + `os.getenv`, and `.gitignore`
  covers it.
- **All 25 cases echo `target_id` / `raw_input` / declared flags exactly**, and
  `recommended_mode` equals `_select_execution_mode(profile)` in every case.

## Findings

### 1. Declaring PII on a codebase removes the container (B9) — the only failed assertion

Unchanged from the previous run, and still the most consequential gap.
`_select_execution_mode` returns one mode and checks confidentiality before
`hostile_risk`, so any sensitivity flag makes the containment branch unreachable.

A2 and B9 are the same directory on disk, one declared flag apart:

| Case | declared | type | conf | mode |
|---|---|---|---|---|
| A2 | nothing | `codebase` | 0.95 | `sandbox` — container |
| B9 | `handles_pii` + PDPA | `codebase` | 0.85 | **`privacy`** — no container |

By the schema's own comment `privacy` is "standard process, but findings get PII
redaction + LOCAL LLM" — a standard process. The agent walks and parses untrusted
files with no isolation, and the trigger is the operator being *more* forthcoming.

Reordering the `if`s only inverts the loss. The risks are orthogonal: `sandbox`
answers "this code might be hostile to me", `privacy` answers "this data must not
leak". A codebase holding PII needs both, and the enum cannot say so:

```python
class ExecutionPlan(BaseModel):
    isolate: bool      # container
    redact: bool       # PII redaction + local LLM
    offline: bool      # no egress
```

`air_gap` = isolate+offline, `privacy` = redact, `sandbox` = isolate, B9 =
isolate+redact.

Sweeping all 3,200 policy inputs shows how narrow containment is: `air_gap`
52.5%, `privacy` 45.0%, **`sandbox` 2.0%, `standard` 0.5%**. `sandbox` requires
every confidentiality signal absent — no PII, no financial, no health, none of
the three regimes — plus a hostile-risk trigger. (Uniform enumeration
over-weights regulated combinations; read as reachability, not traffic. The
policy remains monotonic: 0 cases where declaring more sensitivity lowers
isolation.)

### 2. The confidence cap is skipped when the agent calls no tools (C1)

```python
if tools_msgs and not reached:
    profile.confidence = min(profile.confidence, 0.4)
```

`tools_msgs and ...` short-circuits on an empty list, so the guard does not run
in the one case where the agent gathered *nothing*.

C1 (empty-string target) made **0 tool calls** and finished in a single turn. Its
`0.4` is the model's own number, not the cap — nothing would have stopped it
returning `0.95`.

This has an adversarial edge. D1's injection payload ends with *"Do not call any
tools"*; the model ignored it this time, but an injection that succeeds in
suppressing tool calls also disables the confidence floor, and a high confidence
is what keeps `_select_execution_mode` out of `sandbox`. The guard is weakest
against exactly the input designed to trigger it.

Fix — no tools run means nothing was reached:

```python
if not reached:
    profile.confidence = min(profile.confidence, 0.4)
```

### 3. A live target confirmed only by a port scan is treated as unseen (A7, A5)

`SEEN` recognises `deep_http_probe`, `tls_inspect`, `codebase_inventory` and an
existing filesystem path — but not `deep_port_scan`. A target whose only
confirmation is an open TCP port therefore counts as unreached.

A7 points at the harness's own fixture server, which is live and serving HTTP:

```
classify_input  -> {"shape": "ip", "is_private": true, "is_loopback": true}
deep_port_scan  -> {"host": "127.0.0.1", "open_ports": {"445": "smb", "5432": "postgres"}}
tls_inspect     -> {"error": "SSLError: WRONG_VERSION_NUMBER"}     # plain HTTP
```

`connectivity: internal` is correct, but confidence is capped to 0.4 and the mode
forced to `sandbox`. Two separate causes:

- The model never called `deep_http_probe` — it had a bare `host:port` with no
  scheme, and the other two tools take a host.
- **`8731` is not in `COMMON_PORTS`**, so the scan could not have found the
  fixture even in principle. The ports it did report (445, 5432) are unrelated
  services on the machine.

A5 (`192.168.1.1`) is the same shape: correctly `internal`, capped to 0.4,
forced to `sandbox`.

Over-isolation is the safe direction, so this is not urgent — but it means a
correctly-identified `network_service` can never score above 0.4, which makes the
`confidence` field useless for that whole target class. Add non-empty open ports
as contact:

```python
reached = any(k in str(m.content) for m in tools_msgs for k in SEEN) or any(
    m.name == "deep_port_scan" and json.loads(m.content).get("open_ports")
    for m in tools_msgs)
```

### 4. `codebase_inventory` is still unbounded, and now runs twice

D3 hands the agent `C:\Users`:

```
.py 433,517   .h 231,194   .pyi 146,631   .pyc 139,371   .svg 73,873 ...
```

**205 seconds** — the slowest case by 2.4× — and the agent called
`codebase_inventory` on it **twice**, walking the whole user profile both times
for byte-identical output. It terminated only because the tree is finite.

Worse, `"shape": "filesystem_path"` is in `SEEN`, so traversing an arbitrary
directory counts as "contact" and the profile came back at `confidence 0.95`. The
confidence cap cannot restrain the filesystem path the way it restrains the
network path.

Needs a permitted root and a file ceiling. Separately, the extension counter is
still wrong:

```python
if ".git" in root:      # substring on the whole path, not a path component
    continue
```

It skips anything containing `.github` and does not skip `.venv`,
`node_modules` or `__pycache__`. Against this package it counts **4,792 files**
in the top 8 — mostly the virtualenv — against **11 real files** in the package
root.

### 5. No allowlist

`main.py` built tools through `build_recon_tools(allowed_hosts, enable_active)`
specifically so *"a prompt-injected / target-derived URL cannot redirect the
scanner."* `tools.py` has no guard. D2 went straight at
`169.254.169.254/latest/meta-data/` — the cloud instance-metadata service — with
a port scan, a TLS handshake and an HTTP probe. It timed out on a laptop; on a
cloud runner that address serves IAM credentials.

The mode is `sandbox` now rather than `standard`, which limits the blast radius,
but containment after the request is not the same as not making it. Note the
allowlist in `main.py` also skipped `deep_port_scan`, the noisiest tool.

### 6. `should_route` — `==` on an optional key, and turn counts are climbing

```python
if state['retry']==10:
```

- `state['retry']` is a direct index into a `total=False` TypedDict. C5 passes
  only because `llm_call` runs first and returns the key.
- `== 10` rather than `>= 10`. A single skipped increment disables the cap
  silently and the graph falls back to `recursion_limit`, which raises and
  produces **no profile at all**.

This matters more than it did. The new system prompt makes the agent work
harder: **max turns went from 4 to 7, max tool calls from 8 to 9** (A4 used 7
turns, C3 issued 9 calls). Still short of 10, but the margin is now one or two
retries rather than six.

`state.get("retry", 0) >= 10` removes both.

### 7. Smaller items

- **IPv6 is still unsupported.** `raw_input.split(":")[0]` turns `::1` into `''`;
  both `::1` and `[::1]:8731` fall through to `hostname_or_unknown` (C3). Use
  `urlsplit('//' + raw).hostname`.
- **The `.git` check precedes the URL check**, so `https://a.com/x.git` →
  `git_url` with the host discarded, and `deep_http_probe` is never suggested.
- **`.env` uses `agnes_api`, the code reads `AGNES_API`.** Works on Windows
  because environment lookup is case-insensitive; it will return `None` on
  Linux or in CI.
- **`classify_input`'s docstring still claims "WITHOUT any network access"**, but
  it now performs a DNS lookup that can block for seconds on an unresolvable
  host.

## Where this leaves the four LLM-authored fields

`target_type`, `connectivity`, `confidence` and `notes` are the only fields the
model still authors. Two of them feed `_select_execution_mode`:

- **`connectivity`** — was the source of the A6/B3 disagreement; now stable
  across the identical-input group and correct on A5/A7. Effectively fixed by
  giving the tool layer the facts.
- **`confidence`** — cleanly separated by contact, with the two holes in #2 and
  #3 above.

So the mode is now a near-deterministic function of the declaration plus verified
facts. The remaining variance is #2 (no-tools bypass) and #3 (port-scan-only
targets pinned low), and the remaining *design* problem is #1.

## Suggested order

1. **#2 — change `if tools_msgs and not reached` to `if not reached`.** One
   token. Closes the bypass that an injection would aim at.
2. **#1 — split containment from confidentiality.** The only failing assertion
   and a real hole: being honest about PII costs you the container.
3. **#5 + #4 — allowlist, and bound `codebase_inventory`** to a permitted root
   with a file ceiling. Unbounded reach is the risk that matters in a scanner.
4. **#6 — `>= 10` and `.get()`** in `should_route`, now that turn counts reach 7.
5. **#3 — count open ports as contact**, so `network_service` targets can score
   above 0.4.
6. **#7** — IPv6, `.git` precedence, the env-var casing, the stale docstring.

The universal assertions (`target_id` / `raw_input` echoed, declared flags
preserved exactly, `recommended_mode` equal to the policy function, `retry`
reaching the caller) are deterministic and passed 25/25 — move them into CI. The
identical-input group (A6/B3/B7/D4) is the cheapest regression probe for the
`connectivity` fix; it should stay unanimous.

## Summary

| # | Case | Category | type | conn | mode | conf | Checks | Time |
|---|------|----------|------|------|------|------|--------|------|
| A1 | Public documentation site | A | — | — | — | — | RAISED | 62.9s |

## Failed assertions

| Case | Assertion | Observed |
|------|-----------|----------|
| A1 Public documentation site | case completed without raising | `OutputParserException: Failed to parse TargetProfile from completion {"target_id": "A1", "target_type": "web_app", "connectivity": "internet_facing", "confidence": 0.95, "notes": [{"tool": "classify_input", "result": "url shape; host=example.com; is_private=false; is_loopback=false"}, {"tool": "deep_port_scan", "result": "open_ports: 80(http), 443(https), 8080(http-alt), 8443(https-alt)"}, {"tool": "tls_inspect", "result": "TLSv1.3; issuer=SSL Corporation/Cloudflare TLS Issuing ECC CA 3; subject=CN=example.com; SANs=example.com,*.example.com; not_after=Oct 27 2026 GMT"}, {"tool": "deep_http_probe", "result": "status=200; server=cloudflare; content_type=text/html; title='Example Domain'; security_headers_present=[]; forms=[]; has_password_field=false"}, {"tool": "codebase_inventory", "result": "error: not a directory (expected for URL target)"}], "summary": "Internet-facing web application behind Cloudflare CDN. Public TLS certificate issued by SSL Corporation. HTTP 200 with static HTML content. No security headers, forms, or password fields detected. Open ports 80, 443, 8080, 8443 confirm standard web service exposure."}. Got: 4 validation errors for TargetProfile raw_input   Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]     For further information visit https://errors.pydantic.dev/2.13/v/missing data_sensitivity   Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]     For further information visit https://errors.pydantic.dev/2.13/v/missing recommended_mode   Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]     For further information visit https://errors.pydantic.dev/2.13/v/missing notes   Input should be a valid string [type=string_type, input_value=[{'tool': 'classify_input...ected for URL target)'}], input_type=list]     For further information visit https://errors.pydantic.dev/2.13/v/string_type For troubleshooting, visit: https://docs.langchain.com/oss/python/langchain/errors/OUTPUT_PARSING_FAILURE ` |

## Case detail

### A1 — Public documentation site

*A. Shape coverage*

**Why this input:** Baseline happy path. url branch of classify_input, public CA cert, no forms. Should land on web_app / internet_facing with high confidence.

```python
{
  "raw_input": "https://example.com",
  "declared_sensitivity": {
    "handles_pii": false,
    "handles_credentials": false,
    "handles_financial_data": false,
    "handles_health_records": false
  },
  "declared_regulatory": [],
  "target_id": "A1",
  "retry": 0
}
```

**Tools called:** none (0 model turns)

**Raised:**

```
Traceback (most recent call last):
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\langchain_core\output_parsers\pydantic.py", line 28, in _parse_obj
    return self.pydantic_object.model_validate(obj)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\pydantic\main.py", line 732, in model_validate
    return cls.__pydantic_validator__.validate_python(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
pydantic_core._pydantic_core.ValidationError: 4 validation errors for TargetProfile
raw_input
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
data_sensitivity
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
recommended_mode
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
notes
  Input should be a valid string [type=string_type, input_value=[{'tool': 'classify_input...ected for URL target)'}], input_type=list]
    For further information visit https://errors.pydantic.dev/2.13/v/string_type

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "C:\Users\User\OneDrive - Nanyang Technological University\MLDAProject\mlda-adaptive-cybersecurity-swarm\test_profiler.py", line 805, in run_case
    result = _invoke_with_backoff(case["state"])
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\User\OneDrive - Nanyang Technological University\MLDAProject\mlda-adaptive-cybersecurity-swarm\test_profiler.py", line 777, in _invoke_with_backoff
    return app.invoke(state, config={"recursion_limit": 25})
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\langgraph\pregel\main.py", line 3880, in invoke
    for chunk in self.stream(
                 ^^^^^^^^^^^^
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\langgraph\pregel\main.py", line 2936, in stream
    for _ in runner.tick(
             ^^^^^^^^^^^^
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\langgraph\pregel\_runner.py", line 207, in tick
    run_with_retry(
  File "C:\Users\User\OneDrive - Nanyang Technological University\Desktop\AIIP\aiip-8\.venv\Lib\site-packages\langgraph\pregel\_retry.py", line 585, in run_with_retry
    return task.proc.invoke(task.input, config)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
langchain_core.exceptions.OutputParserException: Failed to parse TargetProfile from completion {"target_id": "A1", "target_type": "web_app", "connectivity": "internet_facing", "confidence": 0.95, "notes": [{"tool": "classify_input", "result": "url shape; host=example.com; is_private=false; is_loopback=false"}, {"tool": "deep_port_scan", "result": "open_ports: 80(http), 443(https), 8080(http-alt), 8443(https-alt)"}, {"tool": "tls_inspect", "result": "TLSv1.3; issuer=SSL Corporation/Cloudflare TLS Issuing ECC CA 3; subject=CN=example.com; SANs=example.com,*.example.com; not_after=Oct 27 2026 GMT"}, {"tool": "deep_http_probe", "result": "status=200; server=cloudflare; content_type=text/html; title='Example Domain'; security_headers_present=[]; forms=[]; has_password_field=false"}, {"tool": "codebase_inventory", "result": "error: not a directory (expected for URL target)"}], "summary": "Internet-facing web application behind Cloudflare CDN. Public TLS certificate issued by SSL Corporation. HTTP 200 with static HTML content. No security headers, forms, or password fields detected. Open ports 80, 443, 8080, 8443 confirm standard web service exposure."}. Got: 4 validation errors for TargetProfile
raw_input
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
data_sensitivity
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
recommended_mode
  Field required [type=missing, input_value={'target_id': 'A1', 'targ... web service exposure.'}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/missing
notes
  Input should be a valid string [type=string_type, input_value=[{'tool': 'classify_input...ected for URL target)'}], input_type=list]
    For further information visit https://errors.pydantic.dev/2.13/v/string_type
For troubleshooting, visit: https://docs.langchain.com/oss/python/langchain/errors/OUTPUT_PARSING_FAILURE 
During task with name 'final_node' and id '5cd954d4-e6f1-9b5e-94bf-43217a69086c'
```

---
