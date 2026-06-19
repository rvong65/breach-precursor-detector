"""Tests for explainability.py — SHAP formatting and optional attribution."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from explainability import (
    append_shap_to_explanations,
    compute_shap_suffixes,
    feature_matrix_from_df,
    format_top_shap_features,
    load_model,
)


class TestFormatTopShapFeatures:
    def test_formats_top_two(self):
        names = ["a", "b", "c"]
        row = np.array([0.01, -0.5, 0.3])
        s = format_top_shap_features(row, names, top_k=2)
        assert "Top features:" in s
        assert "b (-0.50)" in s
        assert "c (+0.30)" in s

    def test_empty_when_all_zero(self):
        assert format_top_shap_features(np.zeros(3), ["a", "b", "c"]) == ""

    def test_mismatched_length_returns_empty(self):
        assert format_top_shap_features(np.array([1.0]), ["a", "b"]) == ""


class TestFeatureMatrixFromDf:
    def test_drops_timestamp(self):
        df = pd.DataFrame({"timestamp": [1], "a": [1.0], "b": [2.0]})
        X = feature_matrix_from_df(df)
        assert "timestamp" not in X.columns
        assert list(X.columns) == ["a", "b"]


class TestLoadModel:
    def test_missing_path_returns_none(self, tmp_path: Path):
        assert load_model(tmp_path / "missing.pkl") is None


class TestComputeShapSuffixes:
    def test_returns_suffix_for_flagged_row(self):
        pytest.importorskip("shap")
        rng = np.random.RandomState(42)
        X = pd.DataFrame(rng.randn(40, 4), columns=[f"f{i}" for i in range(4)])
        model = IsolationForest(n_estimators=50, random_state=42)
        model.fit(X)
        suffixes = compute_shap_suffixes(model, X, X.index[[0]], top_k=2)
        assert 0 in suffixes
        assert "Top features:" in suffixes[0]

    def test_empty_indices(self):
        pytest.importorskip("shap")
        X = pd.DataFrame({"a": [1.0]})
        model = IsolationForest(n_estimators=10, random_state=1)
        model.fit(X)
        assert compute_shap_suffixes(model, X, pd.Index([])) == {}


class TestAppendShapToExplanations:
    def test_appends_when_model_exists(self, tmp_path: Path):
        pytest.importorskip("shap")
        import joblib

        rng = np.random.RandomState(7)
        X = pd.DataFrame(rng.randn(40, 3), columns=["a", "b", "c"])
        model = IsolationForest(n_estimators=50, random_state=42)
        model.fit(X)
        model_path = tmp_path / "model.pkl"
        joblib.dump(model, model_path)

        df = pd.DataFrame(
            {
                "flagged": [True, False, True],
                "explanation": ["Flagged: test (score: -1.0)", "—", "Flagged: x (score: -2.0)"],
                "a": X["a"].iloc[:3].values,
                "b": X["b"].iloc[:3].values,
                "c": X["c"].iloc[:3].values,
            }
        )
        out = append_shap_to_explanations(df, model_path)
        flagged = out.loc[out["flagged"], "explanation"]
        assert any("Top features:" in str(e) for e in flagged)
        assert out.loc[1, "explanation"] == "—"

    def test_no_op_when_model_missing(self, tmp_path: Path):
        df = pd.DataFrame({"flagged": [True], "explanation": ["Flagged: test"]})
        out = append_shap_to_explanations(df, tmp_path / "nope.pkl")
        assert out["explanation"].iloc[0] == "Flagged: test"
