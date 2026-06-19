"""Tests for app.py upload validation and schema normalization."""

from __future__ import annotations

import io
from datetime import datetime

import pandas as pd
import pytest

from app import _ensure_risk_and_flagged, _flagged_events, _normalize_schema, load_uploaded_file


def _valid_csv_bytes() -> bytes:
    df = pd.DataFrame(
        {
            "timestamp": [datetime(2024, 1, 1, 12, 0, 0)],
            "image": [r"C:\Windows\System32\cmd.exe"],
            "parent_image": [r"C:\Windows\explorer.exe"],
            "command_line": ["whoami"],
            "pid": [1000],
            "ppid": [500],
            "event_type": ["4688"],
            "anomaly_score": [-0.2],
        }
    )
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    return buf.getvalue()


class TestNormalizeSchema:
    def test_image_renamed_to_process_image(self):
        df = pd.DataFrame({"image": ["a.exe"], "parent_image": ["b.exe"]})
        out = _normalize_schema(df)
        assert "process_image" in out.columns
        assert out["process_image"].iloc[0] == "a.exe"

    def test_process_image_unchanged_when_present(self):
        df = pd.DataFrame({"process_image": ["a.exe"]})
        out = _normalize_schema(df)
        assert out["process_image"].iloc[0] == "a.exe"


class TestEnsureRiskAndFlagged:
    def test_infers_risk_from_anomaly_score(self):
        df = pd.DataFrame({"anomaly_score": [0.0, 0.5, 1.0, 2.0, 3.0] * 20})
        out = _ensure_risk_and_flagged(df)
        assert "risk_level" in out.columns
        assert set(out["risk_level"].unique()) <= {"Critical", "High", "Medium", "Low", "Normal"}

    def test_flagged_derived_from_risk_level(self):
        df = pd.DataFrame({"risk_level": ["Critical", "Normal", "High"]})
        out = _ensure_risk_and_flagged(df)
        assert out["flagged"].tolist() == [True, False, True]

    def test_explanation_default_empty_string(self):
        df = pd.DataFrame({"risk_level": ["Normal"]})
        out = _ensure_risk_and_flagged(df)
        assert out["explanation"].iloc[0] == ""


class TestFlaggedEvents:
    def test_prefers_confidence_gated_column_over_risk_band(self):
        df = pd.DataFrame(
            {
                "risk_level": ["Critical", "Critical", "Normal"],
                "flagged": [True, False, False],
            }
        )
        out = _flagged_events(df)
        assert len(out) == 1
        assert bool(out.iloc[0]["flagged"])

    def test_falls_back_to_risk_level_when_no_flagged_column(self):
        df = pd.DataFrame({"risk_level": ["Critical", "Normal", "High"]})
        out = _flagged_events(df)
        assert len(out) == 2


class TestLoadUploadedFile:
    def test_valid_csv_returns_dataframe(self):
        content = _valid_csv_bytes()
        df = load_uploaded_file("events.csv", len(content), content)
        assert df is not None
        assert not df.empty
        assert "process_image" in df.columns

    def test_wrong_extension_returns_none(self):
        content = b"not used"
        assert load_uploaded_file("events.txt", len(content), content) is None

    def test_empty_csv_returns_empty_dataframe(self):
        df = pd.DataFrame(
            columns=["timestamp", "image", "parent_image", "command_line", "pid", "ppid", "event_type"]
        )
        buf = io.BytesIO()
        df.to_csv(buf, index=False)
        content = buf.getvalue()
        result = load_uploaded_file("empty.csv", len(content), content)
        assert isinstance(result, pd.DataFrame)
        assert result.empty

    def test_missing_required_columns_returns_none(self):
        buf = io.BytesIO()
        pd.DataFrame({"timestamp": ["2024-01-01"]}).to_csv(buf, index=False)
        content = buf.getvalue()
        assert load_uploaded_file("bad.csv", len(content), content) is None

    def test_invalid_timestamp_returns_none(self):
        df = pd.DataFrame(
            {
                "timestamp": ["not-a-date"],
                "image": ["a.exe"],
                "parent_image": ["b.exe"],
                "command_line": ["x"],
                "pid": [1],
                "ppid": [0],
                "event_type": ["1"],
            }
        )
        buf = io.BytesIO()
        df.to_csv(buf, index=False)
        content = buf.getvalue()
        assert load_uploaded_file("bad_ts.csv", len(content), content) is None

    def test_non_numeric_pid_returns_none(self):
        df = pd.DataFrame(
            {
                "timestamp": ["2024-01-01T12:00:00"],
                "image": ["a.exe"],
                "parent_image": ["b.exe"],
                "command_line": ["x"],
                "pid": ["abc"],
                "ppid": ["def"],
                "event_type": ["1"],
            }
        )
        buf = io.BytesIO()
        df.to_csv(buf, index=False)
        content = buf.getvalue()
        assert load_uploaded_file("bad_pid.csv", len(content), content) is None

    def test_valid_parquet(self):
        df = pd.DataFrame(
            {
                "timestamp": [datetime(2024, 1, 1)],
                "image": ["cmd.exe"],
                "parent_image": ["explorer.exe"],
                "command_line": ["whoami"],
                "pid": [100],
                "ppid": [50],
                "event_type": ["4688"],
            }
        )
        buf = io.BytesIO()
        df.to_parquet(buf, index=False)
        content = buf.getvalue()
        loaded = load_uploaded_file("events.parquet", len(content), content)
        assert loaded is not None
        assert len(loaded) == 1

    def test_corrupt_parquet_returns_none(self):
        assert load_uploaded_file("bad.parquet", 10, b"not parquet") is None

    @pytest.mark.parametrize(
        "filename",
        ["EVENTS.CSV", "data.PARQUET"],
    )
    def test_extension_case_insensitive(self, filename):
        if filename.endswith(".CSV"):
            content = _valid_csv_bytes()
        else:
            df = pd.DataFrame(
                {
                    "timestamp": [datetime(2024, 1, 1)],
                    "image": ["a.exe"],
                    "parent_image": ["b.exe"],
                    "command_line": ["x"],
                    "pid": [1],
                    "ppid": [0],
                    "event_type": ["1"],
                }
            )
            buf = io.BytesIO()
            df.to_parquet(buf, index=False)
            content = buf.getvalue()
        result = load_uploaded_file(filename, len(content), content)
        assert result is not None
