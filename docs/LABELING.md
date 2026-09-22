# Alert labeling (developer / lab only)

Customers use the shipped model (`soc_model.pkl` and the matching vectorizer, scaler, and label encoder). The customer console has no Labeling page, no CSV upload, no train or activate actions, and no “send to training” controls.

Training stays on the lab console. Open it with any one of:

- a stored account role of `developer`
- `SOC_DEVELOPER_EMAILS` (comma-separated logins)
- `SOC_DEV_TRAINING=true` on a lab machine only

Admin and analyst accounts do not get these controls. Leave the settings unset on customer installs.

ML stays **assist-only** by default (`ML_ASSIST_ONLY=true`). Activating a checkpoint swaps artifacts only. It does not turn on ML override.

## Labeling page

1. Open **Labeling** (`/labels`).
2. **Pull from Wazuh** enqueues recent alerts (deduped by summary + full log).
3. Pending rows: **1–4** set severity, **S** skips, **Enter** moves to the next row. Bulk Label / Skip applies to checked rows.
4. Saves update `label_queue`, `alerts_labeled`, and `data/labeled_alerts.csv` (`timestamp,source_ip,username,event_type,severity,description`).

## Other ways in

| Source | What happens |
| --- | --- |
| Triage report / case | Pick severity and **Label**. Same queue and training tables. Duplicates are skipped. |
| Disagree / Low conf | **Queue** sends the event in as `disagreement` or `low_confidence`. Disagreements may also auto-queue, capped (`LABEL_DISAGREEMENT_CAP`, default 20) and deduped. Low confidence is manual. |
| False positives | **Enqueue** on a noisy rule adds up to five recent samples (`fp_review`). |
| CSV | **Import** on Labeling. Header must include `timestamp,source_ip,username,event_type,severity,description`. Optional `analyst_notes`, `label_source`. Invalid severities and empty rows are rejected; the page shows accepted and rejected counts. |

## Train and activate

- **Train candidate** writes `models/checkpoints/<id>/` and leaves the live model in place.
- **Activate** copies that checkpoint onto `soc_model.pkl`, `vectorizer.pkl`, `scaler.pkl`, and `label_encoder.pkl`, then reloads triage.
- The page shows the active name/time and the latest trained name/time.

CLI (lab machines):

```bash
python train_model.py              # writes live artifacts and records the checkpoint
python train_model.py --candidate  # checkpoint only
python train_model.py --activate CHECKPOINT_ID
python evaluate_model.py
```

`evaluate_model.py` does not replace the live model.
