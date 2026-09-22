# False-positive reduction

Lab SOCs generate a lot of routine noise (package managers, PAM sessions, scanners).
Operator-facing severity stays **rules-based**. ML remains assist-only and does not
raise severity on a suppressed or muted alert.

Controls:

1. **Allowlists** — git defaults in `config/allowlists.yml` (IPs, CIDRs, users, hosts, Wazuh rule ids)
2. **Runtime suppresses and mutes** — `data/allowlists_runtime.yml` (or `FP_RUNTIME_ALLOWLIST_PATH`), merged on read
3. **Noise YAML rules** — low/ignore detections such as `rules/dpkg_noise_note.yml` and `rules/pam_session_noise.yml`

The **False positives** page (`/fp-review`) groups recent `triage_events` into similarity
buckets. A bucket is the rule key plus host and user. When both host and user are missing,
a short log fingerprint is included so one line does not stand in for every host.
Developer consoles still have **Enqueue**, which sends a few samples for that rule into
the labeling queue. Customers and analysts suppress or mute; they do not train the model.

## Analyst loop

1. Open **False positives**, or use **Suppress** on a triage row or case.
2. The default scope is **this bucket**. **All hosts for this rule**, or a single IP / user / host, is an explicit choice.
3. **Mute 24h**, **Mute 7d**, or a custom number of hours expires on its own. The row shows the expiry time. **Unmute** ends it early. Expired mutes stop matching and the bucket can be suggested again.
4. **Suppress similar** is permanent. It needs either `FP_SUPPRESS_GATE` distinct analysts (default 2) marking that bucket false positive, or an admin/developer confirmation. Below the gate, the page offers mute or shows that confirmation is required.
5. On a busy, mostly low/ignore bucket, **Accept** saves the default bucket suppress, **Edit** changes the scope, and **Dismiss** hides the suggestion.
6. **Active suppresses** lists who added each runtime suppress or mute, and when. Removing a suppress or unmuting takes effect on the next alert.
7. Git-tracked defaults in `config/allowlists.yml` still apply. Console edits stay in the runtime file so those defaults stay clean.

The dashboard and in-process watchers reload the runtime file when it changes. A process restart is not required after Suppress or Mute.

## Pipeline behaviour

`detection.pipeline.process_alert`:

**normalize → enrich → allowlist match → YAML rules → scoped suppress/mute → triage compose**

- Enrichment and ML assist fields still run.
- Static allowlists and runtime IP / user / host entries match first.
- After YAML rules identify the rule key, an active bucket suppress, entire-rule suppress, or unexpired mute forces severity **low** and recommendation **ignore**.
- A suppress on one host does not match the same rule on another host unless the scope is the entire rule.
- `severity_source` is `allowlist` for a durable suppress and `mute` for a temporary mute.
- ML may still be shown as assist. It is not used to raise the operator-facing severity while the suppress or mute matches.

## Editing allowlists

Git defaults:

```yaml
# config/allowlists.yml
ips: []
cidrs: []
users: []
hosts: []
suppress_wazuh_rule_ids:
  - "2902"
  - "2904"
```

Runtime file (created by the console; safe to edit by hand):

```yaml
# data/allowlists_runtime.yml
suppresses: []   # durable bucket, rule, ip, user, or host entries (who/when)
mutes: []        # temporary entries with expires_at
marks: []        # distinct analysts who marked a bucket false positive
dismissed: []    # buckets whose draft suggestion was dismissed
```

Optional env (see `.env.example`):

```bash
ALLOWLIST_PATH=config/allowlists.yml
FP_RUNTIME_ALLOWLIST_PATH=data/allowlists_runtime.yml
FP_SUPPRESS_GATE=2
FP_DRAFT_MIN_COUNT=5
FP_DRAFT_MIN_PCT=80
FP_MUTE_MAX_HOURS=720
```

Passing an explicit allowlist path into `process_alert` (unit tests) skips the runtime suppress and mute file. Production ingest does not pass one.

Never commit secrets. Keep `.env`, the runtime allowlist, and database files out of git.

## UI

- Navbar: **False positives**
- Triage report and case detail: **Suppress** (mute, false-positive mark, suppress similar)
- URL: `http://127.0.0.1:5000/fp-review` (login required)
- Query: `?limit=500` | `1000` | `2000` (default 1000)
- Draft Accept is shown when a bucket's count is at least `FP_DRAFT_MIN_COUNT` and its low/ignore share is at least `FP_DRAFT_MIN_PCT`
- **Enqueue** stays on the developer console only

## Tests

```bash
pytest tests/test_allowlists.py tests/test_pipeline.py tests/test_fp_review.py tests/test_suppressions.py tests/test_suppress_routes.py -q
```
