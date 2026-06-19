"""Tests for confidence_gating.py — risk levels, gating, explanations, config."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from confidence_gating import (
    DEFAULT_RISK_PERCENTILES,
    add_explanations,
    add_flagged,
    add_risk_level,
    merge_scored_and_features,
    save_config,
    strong_indicator,
)


class TestStrongIndicator:
    def test_suspicious_parent_triggers(self):
        df = pd.DataFrame({"suspicious_parent": [1], "dump_precursor": [0], "hidden_flags": [0]})
        assert strong_indicator(df).iloc[0]

    def test_dump_precursor_triggers(self):
        df = pd.DataFrame({"suspicious_parent": [0], "dump_precursor": [1], "hidden_flags": [0]})
        assert strong_indicator(df).iloc[0]

    def test_hidden_flags_ge_two_triggers(self):
        df = pd.DataFrame({"suspicious_parent": [0], "dump_precursor": [0], "hidden_flags": [2]})
        assert strong_indicator(df).iloc[0]

    def test_hidden_flags_one_does_not_trigger(self):
        df = pd.DataFrame({"suspicious_parent": [0], "dump_precursor": [0], "hidden_flags": [1]})
        assert not strong_indicator(df).iloc[0]

    def test_none_strong_when_all_zero(self):
        df = pd.DataFrame({"suspicious_parent": [0], "dump_precursor": [0], "hidden_flags": [0]})
        assert not strong_indicator(df).iloc[0]

    def test_missing_columns_default_zero(self):
        df = pd.DataFrame({"anomaly_score": [0.0]})
        assert not strong_indicator(df).iloc[0]


class TestAddFlagged:
    def test_flagged_requires_both_score_and_indicator(self, scored_merge_df):
        df, threshold = add_flagged(scored_merge_df.copy(), score_threshold=5.0)
        flagged = df[df["flagged"]]
        assert (flagged["anomaly_score"] < threshold).all()
        assert strong_indicator(flagged).all()

    def test_no_flags_when_threshold_very_low(self, scored_merge_df):
        df, _ = add_flagged(scored_merge_df.copy(), score_threshold=-100.0)
        assert not df["flagged"].any()

    def test_default_threshold_is_fifth_percentile(self):
        df = pd.DataFrame(
            {
                "anomaly_score": list(range(100)),
                "suspicious_parent": [1] * 100,
                "dump_precursor": [0] * 100,
                "hidden_flags": [0] * 100,
            }
        )
        out, threshold = add_flagged(df)
        assert threshold == pytest.approx(float(df["anomaly_score"].quantile(0.05)))

    def test_flagged_column_is_boolean(self, scored_merge_df):
        df, _ = add_flagged(scored_merge_df.copy(), score_threshold=10.0)
        assert df["flagged"].dtype == bool


class TestAddRiskLevel:
    def test_all_risk_levels_assigned(self):
        df = pd.DataFrame({"anomaly_score": np.linspace(-1, 1, 50)})
        out = add_risk_level(df)
        levels = set(out["risk_level"].unique())
        assert levels <= {"Critical", "High", "Medium", "Low", "Normal"}

    def test_lowest_scores_are_critical(self):
        df = pd.DataFrame({"anomaly_score": list(range(100))})
        out = add_risk_level(df)
        min_score_idx = df["anomaly_score"].idxmin()
        assert out.loc[min_score_idx, "risk_level"] == "Critical"

    def test_nan_score_is_normal(self):
        df = pd.DataFrame({"anomaly_score": [np.nan, 0.0]})
        out = add_risk_level(df)
        assert out.loc[0, "risk_level"] == "Normal"

    def test_custom_percentiles(self):
        df = pd.DataFrame({"anomaly_score": [0, 1, 2, 3, 4]})
        out = add_risk_level(df, percentiles={"Critical": 0.5})
        assert out.loc[0, "risk_level"] == "Critical"


class TestMergeScoredAndFeatures:
    def test_merge_preserves_scored_columns(self):
        scored = pd.DataFrame({"anomaly_score": [0.1], "process_image": ["a.exe"]}, index=[0])
        X = pd.DataFrame({"suspicious_parent": [1], "dump_precursor": [0]}, index=[0])
        merged = merge_scored_and_features(scored, X)
        assert "anomaly_score" in merged.columns
        assert "suspicious_parent" in merged.columns

    def test_timestamp_not_duplicated_from_x(self):
        scored = pd.DataFrame({"anomaly_score": [0.1], "timestamp": ["2024-01-01"]}, index=[0])
        X = pd.DataFrame({"suspicious_parent": [1], "timestamp": ["2024-06-01"]}, index=[0])
        merged = merge_scored_and_features(scored, X)
        assert merged["timestamp"].iloc[0] == "2024-01-01"


class TestAddExplanations:
    def test_flagged_row_gets_explanation(self):
        df = pd.DataFrame(
            {
                "flagged": [True],
                "anomaly_score": [-0.5],
                "process_image": ["procdump.exe"],
                "parent_image": ["cmd.exe"],
                "command_line": ["procdump lsass"],
                "dump_precursor": [1],
            }
        )
        out = add_explanations(df)
        assert out["explanation"].iloc[0].startswith("Flagged:")
        assert "procdump" in out["explanation"].iloc[0].lower()

    def test_unflagged_row_gets_dash(self):
        df = pd.DataFrame({"flagged": [False], "anomaly_score": [0.5]})
        out = add_explanations(df)
        assert out["explanation"].iloc[0] == "—"

    def test_lsass_access_in_explanation(self):
        df = pd.DataFrame(
            {
                "flagged": [True],
                "anomaly_score": [-0.3],
                "process_image": ["x.exe"],
                "parent_image": ["y.exe"],
                "command_line": ["access lsass.exe"],
                "dump_precursor": [0],
            }
        )
        out = add_explanations(df)
        assert "lsass" in out["explanation"].iloc[0].lower()


class TestSaveConfig:
    def test_config_json_structure(self, tmp_path: Path):
        save_config(tmp_path, score_threshold=0.05, risk_percentiles=DEFAULT_RISK_PERCENTILES)
        path = tmp_path / "threshold_config.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["score_threshold"] == 0.05
        assert "risk_level_bounds" in data
        assert "strong_indicator_definition" in data
        assert data.get("shap_enabled") is False
