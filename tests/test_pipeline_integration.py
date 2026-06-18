"""End-to-end pipeline smoke test on synthetic events (no raw log files)."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from confidence_gating import add_explanations, add_flagged, add_risk_level, merge_scored_and_features, save_config
from feature_engineering import build_X_features, build_heuristic_labels, prep_events
from train_isolation_forest import prepare_X_train, score_data, train_model


@pytest.mark.integration
def test_pipeline_smoke_synthetic(minimal_events, tmp_path: Path):
    """Feature engineering → IF → gating → artifacts on in-memory synthetic data."""
    prepped = prep_events(minimal_events)
    assert not prepped.empty

    X = build_X_features(prepped)
    y = build_heuristic_labels(X)
    assert len(y) == len(X)

    X_train = prepare_X_train(X)
    model = train_model(X_train, n_estimators=30, random_state=42)
    scored = score_data(model, X, prepped, X_train)

    merged = merge_scored_and_features(scored, X)
    merged = add_risk_level(merged)
    merged, threshold = add_flagged(merged, score_threshold=None)
    merged = add_explanations(merged)

    assert "flagged" in merged.columns
    assert "explanation" in merged.columns
    assert "risk_level" in merged.columns

    out_dir = tmp_path / "output"
    out_dir.mkdir()
    save_config(out_dir, threshold, {"Critical": 0.02, "High": 0.05, "Medium": 0.10, "Low": 0.20})

    config_path = out_dir / "threshold_config.json"
    config = json.loads(config_path.read_text())
    assert "score_threshold" in config

    merged.to_parquet(out_dir / "scored_events_gated.parquet")
    assert (out_dir / "scored_events_gated.parquet").exists()

    flagged = merged[merged["flagged"]]
    for _, row in flagged.iterrows():
        assert row["explanation"].startswith("Flagged:")
