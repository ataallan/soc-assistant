# Detection Phase A

Phase A adds a stable detection path in front of the existing triage / ML assist stack:

**raw alert → normalize → enrich → YAML rules (with explain) → triage_engine (rules + ML assist)**

Entry point: `detection.pipeline.process_alert(raw) → result`.

CLI watchers (`watch_csv`, `watch_wazuh`) and the dashboard (via those watchers) call this path through `soc_triage_cli.analyze_and_predict`.

ML remains **assist-only** by default (`ML_ASSIST_ONLY=true`). YAML + keyword rules set the operator-facing severity; ML confidence is stored for analytics and shown as assist in the report UI.

## Layout

| Path | Role |
| --- | --- |
| `detection/normalize.py` | Stable internal alert dict from Wazuh-ish dicts / CSV rows / strings |
| `detection/enrichment.py` | Offline IP classification, optional asset inventory, optional AbuseIPDB |
| `detection/pipeline.py` | Orchestrates normalize → enrich → YAML → triage compose |
| `rules/engine.py` | Load / evaluate YAML rules |
| `rules/*.yml` | Sample detection rules with `explain` templates |
| `config/assets.yml` | Sample asset inventory (YAML) |
| `data/asset_inventory.csv` | Sample asset inventory (CSV, merges with YAML) |

## Normalized alert fields

`tenant_id` (default `local`), `source`, `event_id`, `timestamp`, `rule_id`, `rule_description`, `severity_hint`, `src_ip`, `dst_ip`, `user`, `host`, `mitre_technique`, `raw_message`, `extras`.

Normalization is defensive and never raises.

## Enrichment

Controlled by `ENRICHMENT_ENABLED` (default `true`).

- **RFC1918 / IP class** — private, public, loopback, link-local, etc.
- **Asset inventory** — `config/assets.yml` and/or `data/asset_inventory.csv`
- **AbuseIPDB** — only when `ABUSEIPDB_API_KEY` is set; skipped in pytest / offline

## How to add a YAML rule

Drop a new `rules/<name>.yml` file (or append under a `rules:` list). Required keys: `id`, `name`, `enabled`, `severity`, `priority`, `conditions` (AND list). Each condition has `field` (dotted path into the alert / `enrichment.*` / helpers like `text`, `src_ip_class`, `asset_criticality`), `op` (`eq` | `contains` | `regex` | `in_list` | `exists`), and `value` / `values`. Optional: `mitre`, `explain` (supports `{src_ip}`, `{user}`, `{host}`, `{asset_name}`, `{rule_id}`, etc.). On match, the engine returns the rule with a rendered explain string; pipeline severity is the **max** of YAML matches and the existing keyword rules in `triage_engine`. Reload is automatic on process restart (or call `load_rules(force_reload=True)`). Keep rules offline and deterministic — no network in the evaluator.

## Pipeline result (high level)

`process_alert` returns severity, recommendation, `rule_severity`, `matched_rules` (id/name/severity/explain), `matched_rule_id`, `rule_explain`, enrichment + notes, and ML assist fields (`ml_severity`, `ml_confidence`, `ml_assist`, `severity_source`).

The triage report UI shows the top matched rule id + explain in a **Detection** column when present.

## Next step (not in Phase A)

A multi-tenant customer ingest API (authenticated alert intake per tenant) is intentionally **not** built here. Phase A keeps `tenant_id="local"` and local CSV / Wazuh watchers. Multi-tenant ingest is the natural follow-on once detection normalize/enrich/rules are stable.

## Tests

```bash
pytest tests/test_normalize.py tests/test_enrichment.py tests/test_rules_engine.py tests/test_pipeline.py -q
```

All detection unit tests are offline (no network).

## False positives

Allowlists (`config/allowlists.yml`), noise YAML rules, and the `/fp-review` UI are documented in [FALSE_POSITIVES.md](FALSE_POSITIVES.md).
