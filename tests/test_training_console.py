"""Developer training console: queue, CSV, checkpoints, FP, disagreement, RBAC."""

from __future__ import annotations

import importlib
from io import BytesIO

import db
import labeling
from model_registry import ARTIFACTS, activate_checkpoint, checkpoint_status, train_candidate


def _tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "label_test.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SOC_DEV_TRAINING", raising=False)
    monkeypatch.setenv("SOC_DEVELOPER_EMAILS", "")
    db.reset_connection()
    db.init_db(db_path)
    monkeypatch.setattr(db, "LABELED_CSV_PATH", tmp_path / "labeled_alerts.csv")
    return db_path


def test_submit_correct_label_dedupes(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    item = {
        "summary": "brute force",
        "full_log": "sshd: Failed password for root from 10.0.0.8",
        "source_ip": "10.0.0.8",
        "username": "root",
        "event_type": "failed_login",
        "event_timestamp": "2025-01-01T00:00:00Z",
    }
    first = labeling.submit_correct_label(item, "high", source="triage", db_path=db_path)
    second = labeling.submit_correct_label(item, "low", source="correction", db_path=db_path)
    assert first["inserted"] == 1
    assert first["labeled"] is True
    assert second["inserted"] == 0
    assert second["skipped_dupes"] == 1
    assert second["labeled"] is False
    assert db.label_queue_counts(db_path=db_path)["labeled"] == 1
    assert db.label_queue_counts(db_path=db_path)["alerts_labeled"] == 1
    pending = db.list_label_queue(status="labeled", db_path=db_path)
    assert pending[0]["source"] == "triage"
    body = (tmp_path / "labeled_alerts.csv").read_text(encoding="utf-8")
    assert "high" in body
    assert "10.0.0.8" in body


def test_csv_import_accepts_and_rejects(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    text = "\n".join(
        [
            "timestamp,source_ip,username,event_type,severity,description,analyst_notes,label_source",
            "2025-01-01T00:00:00Z,10.0.0.1,alice,failed_login,high,brute force,note,human",
            "2025-01-01T00:01:00Z,10.0.0.2,bob,failed_login,nope,bad severity,,human",
            ",,,, ,,,",
            "2025-01-01T00:00:00Z,10.0.0.1,alice,failed_login,high,brute force,dup,human",
        ]
    )
    result = labeling.import_labeled_csv_text(text, db_path=db_path)
    assert result["ok"] is True
    assert result["accepted"] == 1
    assert result["rejected"] == 2
    assert result["skipped_dupes"] == 1
    again = labeling.import_labeled_csv_text(text, db_path=db_path)
    assert again["accepted"] == 0
    assert again["skipped_dupes"] >= 1

    missing = labeling.import_labeled_csv_text("severity,description\nhigh,x\n", db_path=db_path)
    assert missing["ok"] is False
    assert missing["accepted"] == 0


def test_checkpoint_train_does_not_replace_active_until_activate(tmp_path, monkeypatch):
    root = tmp_path / "models_root"
    root.mkdir()
    monkeypatch.setenv("SOC_MODEL_ROOT", str(root))
    for name in ARTIFACTS:
        (root / name).write_text("live-" + name, encoding="utf-8")

    def fake_train(*_args, **kwargs):
        for key in ("model_file", "vectorizer_file", "scaler_file", "label_encoder_file"):
            path = kwargs[key]
            open(path, "w", encoding="utf-8").write("candidate")
        return {"ok": True, "model": "logreg", "n_samples": 4, "cv_macro_f1": 0.5}

    import train_model

    monkeypatch.setattr(train_model, "train_ml_model", fake_train)
    meta = train_candidate()
    assert meta and meta["id"]
    assert (root / "soc_model.pkl").read_text(encoding="utf-8").startswith("live-")
    status = checkpoint_status()
    assert status["latest"]["name"] == meta["id"]
    assert status["active"]["name"] == "shipped"

    activated = activate_checkpoint(meta["id"], reload=False)
    assert activated["id"] == meta["id"]
    assert (root / "soc_model.pkl").read_text(encoding="utf-8") == "candidate"
    assert (root / "vectorizer.pkl").read_text(encoding="utf-8") == "candidate"
    kept = root / "models" / "checkpoints" / meta["id"] / "soc_model.pkl"
    assert kept.read_text(encoding="utf-8") == "candidate"
    assert checkpoint_status()["active"]["name"] == meta["id"]


def test_fp_enqueue_samples_for_rule(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    events = [
        {"matched_rule_id": "2902", "log": "dpkg install a", "severity": "low", "id": 1},
        {"matched_rule_id": "2902", "log": "dpkg install b", "severity": "low", "id": 2},
        {"matched_rule_id": "2902", "log": "dpkg install a", "severity": "low", "id": 3},
        {"matched_rule_id": "5710", "log": "sshd failed", "severity": "high", "id": 4},
    ]
    result = labeling.enqueue_fp_samples(events, "2902", limit=5, db_path=db_path)
    assert result["inserted"] == 2
    pending = db.list_label_queue(status="pending", db_path=db_path)
    assert len(pending) == 2
    assert {row["source"] for row in pending} == {"fp_review"}
    assert all(row["rule_id"] == "2902" for row in pending)


def test_disagreement_auto_queue_is_capped_and_skips_low_confidence(tmp_path, monkeypatch):
    db_path = _tmp_db(tmp_path, monkeypatch)
    disagree = {
        "log": "malware beacon one",
        "severity": "high",
        "rule_severity": "high",
        "ml_prediction": "low",
        "ml_confidence": 0.91,
        "severity_source": "rules",
        "ip": "10.1.1.1",
        "user": "root",
    }
    first = labeling.maybe_auto_queue_disagreement(
        disagree, db_path=db_path, enabled=True, cap=1, threshold=0.7
    )
    assert first["inserted"] == 1
    assert first["reason"] == "disagreement"
    second = labeling.maybe_auto_queue_disagreement(
        {**disagree, "log": "malware beacon two"},
        db_path=db_path,
        enabled=True,
        cap=1,
        threshold=0.7,
    )
    assert second["inserted"] == 0
    assert second["reason"] == "capped"
    low = labeling.maybe_auto_queue_disagreement(
        {
            "log": "quiet heartbeat",
            "severity": "low",
            "rule_severity": "low",
            "ml_prediction": "low",
            "ml_confidence": 0.2,
            "severity_source": "rules",
        },
        db_path=db_path,
        enabled=True,
        cap=5,
        threshold=0.7,
    )
    assert low["inserted"] == 0
    assert low["reason"] == "low_confidence"
    disabled = labeling.maybe_auto_queue_disagreement(
        {**disagree, "log": "malware beacon three"},
        db_path=db_path,
        enabled=False,
        cap=5,
    )
    assert disabled["reason"] == "disabled"
    pending = db.list_label_queue(status="pending", db_path=db_path)
    assert len(pending) == 1
    assert pending[0]["source"] == "disagreement"


def _dashboard_client(tmp_path, monkeypatch, *, developer_email="", admin_email="admin@example.com"):
    db_path = tmp_path / "dash.db"
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("SOC_EMAIL_2FA", "false")
    monkeypatch.setenv("SOC_DEV_TRAINING", "")
    monkeypatch.setenv("SOC_DEVELOPER_EMAILS", developer_email)
    monkeypatch.setenv("SOC_ADMIN_EMAILS", admin_email)
    monkeypatch.setenv("SOC_USERS_FILE", str(tmp_path / "users.csv"))
    monkeypatch.setenv("CONTAINMENT_MODE", "simulated")
    db.reset_connection()
    db.init_db(db_path)
    monkeypatch.setattr(db, "LABELED_CSV_PATH", tmp_path / "labeled_alerts.csv")
    import dashboard

    importlib.reload(dashboard)
    dashboard.app.config["TESTING"] = True
    dashboard.app.config["WTF_CSRF_ENABLED"] = False
    return dashboard.app.test_client(), dashboard


def _json_headers():
    return {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}


def test_customer_admin_and_analyst_cannot_train(tmp_path, monkeypatch):
    client, _dashboard = _dashboard_client(tmp_path, monkeypatch)
    for user in ("admin@example.com", "analyst@example.com"):
        with client.session_transaction() as sess:
            sess["user"] = user
        home = client.get("/")
        assert home.status_code == 200
        body = home.data.decode("utf-8")
        assert 'href="/labels"' not in body
        assert "Train candidate" not in body
        assert "Train model" not in body

        page = client.get("/labels")
        assert page.status_code in (302, 403)

        for path in ("/labels/retrain", "/labels/activate", "/labels/from-event", "/fp-review/enqueue"):
            resp = client.post(path, headers=_json_headers(), json={})
            assert resp.status_code == 403, path
            assert resp.get_json()["ok"] is False

        upload = client.post(
            "/labels/upload",
            headers=_json_headers(),
            data={"file": (BytesIO(b"timestamp,source_ip,username,event_type,severity,description\n"), "rows.csv")},
            content_type="multipart/form-data",
        )
        assert upload.status_code == 403


def test_developer_labels_page_and_event_enqueue(tmp_path, monkeypatch):
    client, _dashboard = _dashboard_client(
        tmp_path, monkeypatch, developer_email="dev@example.com", admin_email="admin@example.com"
    )
    event_id = db.insert_triage_event(
        {
            "timestamp": "2025-01-01T00:00:00Z",
            "log": "suspicious login from 203.0.113.9 for user dave",
            "severity": "medium",
            "ml_prediction": "high",
            "ml_confidence": 0.88,
            "rule_based": "investigate",
            "severity_source": "rules",
            "user": "dave",
            "ip": "203.0.113.9",
        }
    )
    with client.session_transaction() as sess:
        sess["user"] = "dev@example.com"

    page = client.get("/labels")
    assert page.status_code == 200
    html = page.data.decode("utf-8")
    assert "Train candidate" in html
    assert "Activate" in html
    assert "Import" in html
    assert 'href="/labels"' in client.get("/").data.decode("utf-8")

    report = client.get("/report")
    assert report.status_code == 200
    report_html = report.data.decode("utf-8")
    assert "/labels/from-event" in report_html
    assert "Disagree" in report_html

    saved = client.post(
        "/labels/from-event",
        data={"triage_event_id": str(event_id), "severity": "high"},
        headers=_json_headers(),
    )
    assert saved.status_code == 200
    payload = saved.get_json()
    assert payload["ok"] is True
    assert payload["labeled"] is True
    assert db.label_queue_counts()["alerts_labeled"] >= 1

    import model_registry

    monkeypatch.setattr(
        model_registry,
        "train_candidate",
        lambda *args, **kwargs: {"id": "cand", "created_at": "2026-01-01T00:00:00+00:00"},
    )
    trained = client.post("/labels/retrain", headers=_json_headers())
    assert trained.status_code == 200
    assert trained.get_json()["ok"] is True

    queued = db.insert_label_queue_items(
        [{"summary": "heartbeat", "full_log": "benign heartbeat from agent"}],
    )
    qid = queued["ids"][0]
    saved_form = client.post(
        "/labels/save",
        data={"id": str(qid), "severity": "low"},
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )
    assert saved_form.status_code == 200
    assert saved_form.get_json()["ok"] is True
    assert saved_form.get_json()["label_severity"] == "low"
