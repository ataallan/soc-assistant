# Model assessment — AI SOC Assistant (capstone)

**Verdict for Allan:** The ML severity model is **good enough for a capstone demo**, not for real SOC triage in production. Strong hold-out scores on ~111 rows are still a caution signal (easy separability / lexical cues), not proof of operational readiness.

---

## What changed in this iteration

| Change | Why |
| --- | --- |
| TF-IDF `ngram_range=(1,2)`, `max_features=5000` | Richer text signal without leaving sklearn |
| Dropped raw Unix timestamp + `source_ip_num` | Those features memorize demo IPs/times; weak for security semantics |
| Kept **hour-of-day** only (scaled) | Weak circadian prior; less leakage than raw timestamp |
| Stratified train/test + stratified CV model selection | Fairer splits; pick LogReg / RF / Calibrated LogReg by macro F1 |
| **Full-data refit** in `train_model.py` for saved `.pkl` | Deployment artifacts use all labels; `evaluate_model.py` stays the honest hold-out |
| Hybrid inference in `triage_engine` | Rules `critical` always wins; low ML confidence falls back to rules |

**Still not production-ready** — N≈111 labeled rows.

---

## What the model is

| Piece | Detail |
| --- | --- |
| Task | Multi-class **severity** prediction: `high` / `medium` / `low` |
| Algorithm | Selected among LogReg / RandomForest / CalibratedClassifierCV (sklearn only) |
| Text features | TF-IDF (`ngram_range=(1,2)`, `min_df=1`, `max_features=5000`) over `event_type + description + username` |
| Numeric features | Hour-of-day (0–23), `StandardScaler` — **no** raw IP / Unix timestamp |
| Artifacts | `soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, `label_encoder.pkl` |
| Training data | `data/sample_logs.csv` (**111** labeled rows) |
| Training entrypoints | `train_model.py` (CV select → **refit full data**), `evaluate_model.py` (honest hold-out report only) |

Class balance (full CSV):

```
high      55
medium    34
low       22
```

There is **no `critical` class** in the labeled CSV; critical comes from **rule-based** phrase/numeric logic in `triage_engine.classify_severity`.

---

## Metrics on hold-out

Run `python evaluate_model.py` and read [evaluation_report.md](evaluation_report.md). Numbers will change with the new pipeline; treat them as a **reproducible demo metric**, not a SOC SLA.

### How to read a strong score

On a tiny, synthetic-looking sample set, high accuracy is **not** evidence the model generalizes. Likely contributors:

1. **Tiny N** — ~34 test rows; one lucky split can look excellent.
2. **Strong lexical cues** — `event_type` / `description` strings are almost labels in disguise.
3. **Repeated phrasings** — usernames/patterns reused across rows.
4. **Imbalance** — `high` dominates.

---

## How the model is used at inference vs rules

### `triage_engine.py`

- Loads artifacts at import (`load_ml_model`).
- `analyze_log()` hybrid policy:
  1. If rules say **`critical`** → keep **`critical`**.
  2. Else if ML missing or `max(proba) < ML_CONFIDENCE_THRESHOLD` (default **0.70**) → use **rule severity**.
  3. Else use **ML severity**.
- **`recommendation`** (`escalate` / `investigate` / `ignore`) always comes from **`rule_based_triage(log)`**.
- **`should_auto_contain()`** — separate gate for automatic blocks (agreement / rules_critical / rules_only / disagreement / low_confidence).

### `soc_triage_cli.py`

- Parallel ML path for `ml_prediction` + confidence columns (same text + hour features).
- Auto-block/email only when the agreement gate allows; skipped containment is logged with an operator-friendly note.

### Dashboard

- Watchers / reports / analytics consume the same pipeline columns.

**Bottom line:** Live triage is a **rules + ML hybrid**. Rules are the safety net for critical TTPs and low-confidence ML.

---

## Production-ready?

| Question | Answer |
| --- | --- |
| Capstone / portfolio demo? | **Yes** — clearer features, CV selection, hybrid guardrails. |
| Real SOC auto-triage / auto-block? | **No.** |
| Why not? | ~100 rows; no external validation; limited calibration; blocking on model output alone would be unsafe. |

**Honest one-liner for Allan’s defense:**  
*“The model demonstrates an end-to-end ML triage pipeline on a small labeled set. Hold-out metrics reflect the demo dataset, not production generalization. Rules remain the safety net; we never auto-block on ML alone.”*

---

## Suggested upgrades

Prioritized for Allan after the capstone:

1. **More labeled data** — thousands of analyst-labeled alerts (include `critical`); stratify by Wazuh rule id / MITRE tactic.
2. **Time-split validation** — ✅ **implemented (light):** `evaluate_model.py` prefers a time-ordered hold-out (sort by `timestamp`, last 30% test) when timestamps parse; random stratified remains as comparison. Primary “honest” metrics in `evaluation_report.md` are the time-split when available.
3. **Calibration / confidence threshold** — ✅ **implemented:** `ML_CONFIDENCE_THRESHOLD` (default **0.70**, via `.env`) gates auto-containment when ML is used; hybrid severity still falls back to rules on low confidence. Further calibration (temperature scaling, etc.) still optional.
4. **Ensemble with rules** — ✅ **implemented:** `should_auto_contain()` requires rule escalate **and** ML agreement on high (or rules-`critical` alone) before automatic containment.
5. **No auto-block on ML alone** — ✅ **implemented:** disagreement / low confidence skips containment with an operator-friendly note; ML-missing falls back to `rules_only` audit; containment modes (`simulated` / preview / stub) unchanged.
6. **Richer features (later)** — rule_id, agent role, geo/ASN, failure counts; still avoid raw IP-as-int as a primary signal.
7. **Optional LightGBM / XGBoost later** — only after N is larger and deps are justified; sklearn RF/LogReg are enough for the demo.
8. **Ops** — drift checks, human-in-the-loop review queue, periodic retrain with fresh labels.

### What we already did now

- Text-first TF-IDF bigrams; dropped memorization-prone IP/raw timestamp.
- Stratified CV model pick + full-data refit for artifacts.
- Soft hybrid: critical rules win; low ML confidence → rules.
- **Rule+ML agreement gate** for auto-containment (`should_auto_contain`) + env confidence threshold.
- Time-ordered hold-out in `evaluate_model.py` (primary) alongside random stratified.
- Honest docs: this file + `evaluate_model.py` hold-out (does not overwrite full-data `.pkl`).

---

## Reproduce

```bash
source .venv/bin/activate   # or .venv\Scripts\activate
python train_model.py       # CV select + full-data artifacts
python evaluate_model.py    # honest hold-out report
pytest -q
```

Related: [evaluation_report.md](evaluation_report.md), [ARCHITECTURE.md](ARCHITECTURE.md), [DEMO.md](DEMO.md).
