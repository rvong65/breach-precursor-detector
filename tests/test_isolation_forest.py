"""Tests for train_isolation_forest.py — model train/score helpers."""

from __future__ import annotations

import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from train_isolation_forest import prepare_X_train, score_data, train_model


@pytest.fixture
def feature_matrix() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "suspicious_parent": [0, 1, 0, 1, 0, 1, 0, 0, 1, 0],
            "dump_precursor": [0, 0, 1, 1, 0, 0, 0, 1, 0, 0],
            "hidden_flags": [0, 1, 0, 2, 0, 0, 1, 0, 0, 3],
            "cmd_entropy": [1.0, 2.0, 1.5, 3.0, 0.5, 1.2, 2.5, 1.8, 0.9, 2.2],
            "timestamp": pd.date_range("2024-01-01", periods=10, freq="min"),
        }
    )


class TestPrepareXTrain:
    def test_drops_non_numeric_timestamp(self, feature_matrix):
        X_train = prepare_X_train(feature_matrix)
        assert "timestamp" not in X_train.columns
        assert len(X_train.columns) == 4

    def test_fills_nan_with_zero(self):
        df = pd.DataFrame({"a": [1.0, None], "b": [2.0, 3.0]})
        X_train = prepare_X_train(df)
        assert X_train["a"].iloc[1] == 0.0


class TestTrainModel:
    def test_returns_fitted_isolation_forest(self, feature_matrix):
        X_train = prepare_X_train(feature_matrix)
        model = train_model(X_train, n_estimators=50, random_state=42)
        assert isinstance(model, IsolationForest)
        assert hasattr(model, "predict")

    def test_reproducible_with_random_state(self, feature_matrix):
        X_train = prepare_X_train(feature_matrix)
        m1 = train_model(X_train, n_estimators=30, random_state=99)
        m2 = train_model(X_train, n_estimators=30, random_state=99)
        assert (m1.predict(X_train) == m2.predict(X_train)).all()


class TestScoreData:
    def test_output_has_anomaly_score_and_is_anomaly(self, feature_matrix):
        X_train = prepare_X_train(feature_matrix)
        model = train_model(X_train, n_estimators=50, random_state=42)
        events = pd.DataFrame(
            {
                "timestamp": feature_matrix["timestamp"],
                "process_image": ["a.exe"] * len(feature_matrix),
                "parent_image": ["b.exe"] * len(feature_matrix),
                "command_line": ["x"] * len(feature_matrix),
                "event_type": ["1"] * len(feature_matrix),
            },
            index=feature_matrix.index,
        )
        scored = score_data(model, feature_matrix, events, X_train)
        assert "anomaly_score" in scored.columns
        assert "is_anomaly" in scored.columns
        assert len(scored) == len(feature_matrix)

    def test_trace_columns_merged_from_events(self, feature_matrix):
        X_train = prepare_X_train(feature_matrix)
        model = train_model(X_train, n_estimators=30, random_state=1)
        events = pd.DataFrame(
            {
                "timestamp": feature_matrix["timestamp"],
                "process_image": ["cmd.exe"] * len(feature_matrix),
                "command_line": ["whoami"] * len(feature_matrix),
            },
            index=feature_matrix.index,
        )
        scored = score_data(model, feature_matrix, events, X_train)
        assert "process_image" in scored.columns
        assert scored["process_image"].iloc[0] == "cmd.exe"
