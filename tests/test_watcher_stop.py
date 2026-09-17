"""Watcher stop_event should exit promptly without network I/O."""

import threading
import time
from unittest.mock import patch

from soc_triage_cli import watch_csv, watch_wazuh


def test_watch_csv_stops_quickly(tmp_path):
    # Missing file keeps the loop in the sleep branch (no analyze / network)
    missing = str(tmp_path / "does_not_exist.csv")
    stop = threading.Event()

    started = time.monotonic()
    thread = threading.Thread(
        target=watch_csv,
        kwargs={"file_path": missing, "interval": 5, "stop_event": stop},
        daemon=True,
    )
    thread.start()
    time.sleep(0.2)
    stop.set()
    thread.join(timeout=2.0)
    elapsed = time.monotonic() - started

    assert not thread.is_alive(), "CSV watcher should exit after stop_event"
    assert elapsed < 2.5, f"watcher took too long to stop: {elapsed:.2f}s"


def test_watch_wazuh_stops_quickly():
    stop = threading.Event()

    with patch("soc_triage_cli.fetch_wazuh_alert_details", return_value=[]), patch(
        "soc_triage_cli.analyze_and_predict"
    ):
        started = time.monotonic()
        thread = threading.Thread(
            target=watch_wazuh,
            kwargs={"interval": 5, "stop_event": stop},
            daemon=True,
        )
        thread.start()
        time.sleep(0.2)
        stop.set()
        thread.join(timeout=2.0)
        elapsed = time.monotonic() - started

    assert not thread.is_alive(), "Wazuh watcher should exit after stop_event"
    assert elapsed < 2.5, f"watcher took too long to stop: {elapsed:.2f}s"
