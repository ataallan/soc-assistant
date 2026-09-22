# False-positive reduction

Lab SOCs generate a lot of routine noise (package managers, PAM sessions, scanners).
This project keeps **operator-facing severity rules-based** (ML assist-only) and adds
two FP controls:

1. **Allowlists** — `config/allowlists.yml` (IPs, CIDRs, users, hosts, Wazuh rule-id suppress)
2. **Noise YAML rules** — low/ignore detections such as `rules/dpkg_noise_note.yml` and `rules/pam_session_noise.yml`

The **FP review** page (`/fp-review`) shows which rule keys dominate recent `triage_events`
so you can tune allowlists weekly. On a developer console, **Enqueue** sends a few samples
for that rule into the labeling queue.

## Weekly analyst loop

1. Open **[FP review](/fp-review)** (navbar → FP review). Scan the top rows by volume.
2. Prefer candidates with high **count** and high **% low/ignore** — those are usually safe to suppress.
3. Edit `config/allowlists.yml`:
   - Trusted scanners / jump boxes → `ips` or `cidrs`
   - Service accounts → `users`
   - Lab agents → `hosts`
   - Known-noisy Wazuh Manager rule ids → `suppress_wazuh_rule_ids` (lab defaults include `2902` / `2904` for dpkg)
4. Optionally refine noise YAML under `rules/` (keep malware / CVE / DNS rules intact).
5. Restart the dashboard or CLI watchers so the allowlist cache reloads
   (or set `ALLOWLIST_PATH` to a custom file and restart).
6. Spot-check new triage rows: allowlisted alerts should show severity **low**,
   recommendation **ignore**, and an allowlist note in explain / enrichment notes.
7. Record what you suppressed (ticket / runbook) so true positives are not buried.

## Pipeline behaviour

`detection.pipeline.process_alert`:

**normalize → enrich → allowlist match → YAML rules → triage compose**

- Enrichment and ML assist fields still run.
- If the alert matches an allowlist entry **or** its Wazuh `rule_id` is in
  `suppress_wazuh_rule_ids`, severity is forced to **low**, recommendation to **ignore**,
  and high YAML escalations are skipped. Matched YAML rules may still be recorded for explainability.
- `severity_source` becomes `allowlist` when suppressed this way.

## Editing allowlists

```yaml
# config/allowlists.yml
ips:
  - "203.0.113.10"
cidrs:
  - "10.0.0.0/8"
users:
  - "vagrant"
hosts:
  - "lab-scanner"
suppress_wazuh_rule_ids:
  - "2902"
  - "2904"
  # - "5501"   # PAM session opened
  # - "5502"   # PAM session closed
```

Optional env override (see `.env.example`):

```bash
ALLOWLIST_PATH=/absolute/or/relative/path/to/allowlists.yml
```

Never commit secrets — allowlists are not credentials, but keep `.env` and DB files out of git.

## UI

- Navbar: **FP review** (between Labeling and System)
- URL: `http://127.0.0.1:5000/fp-review` (login required)
- Query: `?limit=500` | `1000` | `2000` (default 1000)

## Tests

```bash
pytest tests/test_allowlists.py tests/test_pipeline.py tests/test_fp_review.py -q
```
