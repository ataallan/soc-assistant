"""Detection Phase A: normalize → enrich → YAML rules → triage compose."""

from detection.pipeline import process_alert

__all__ = ["process_alert"]
