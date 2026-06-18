"""Tests for loaders/schema.py — unified schema normalizers and sanity helpers."""

from __future__ import annotations

import pandas as pd
import pytest

from loaders.schema import (
    SUSPICIOUS_KEYWORDS,
    UNIFIED_COLUMNS,
    normalize_4688,
    normalize_falcon,
    normalize_sysmon,
    null_summary,
    suspicious_mask,
    to_unified,
)


class TestNormalizeFalcon:
    def test_maps_core_columns(self):
        raw = pd.DataFrame(
            {
                "ProcessStartTime": [1658910730.0],
                "event_simpleName": ["ProcessRollup2"],
                "ImageFileName": [r"C:\Windows\cmd.exe"],
                "ParentBaseFileName": ["explorer.exe"],
                "CommandLine": ["whoami"],
                "RawProcessId": [100],
                "ParentProcessId": [50],
            }
        )
        out = normalize_falcon(raw)
        assert out["source"].iloc[0] == "falcon"
        assert out["process_image"].iloc[0] == r"C:\Windows\cmd.exe"
        assert out["pid"].iloc[0] == 100

    def test_empty_returns_unified_columns(self):
        out = normalize_falcon(pd.DataFrame())
        for col in UNIFIED_COLUMNS:
            assert col in out.columns


class TestNormalize4688:
    def test_maps_hex_pids(self):
        raw = pd.DataFrame(
            {
                "system_time": ["2024-01-01T12:00:00"],
                "NewProcessId": ["0x3e8"],
                "ProcessId": ["0x1f4"],
                "NewProcessName": [r"C:\cmd.exe"],
                "ParentProcessName": ["explorer.exe"],
                "CommandLine": ["calc"],
            }
        )
        out = normalize_4688(raw)
        assert out["pid"].iloc[0] == 0x3E8
        assert out["event_type"].iloc[0] == "4688"


class TestNormalizeSysmon:
    def test_event_id_preserved(self):
        raw = pd.DataFrame(
            {
                "EventID": [10],
                "UtcTime": ["2024-01-01 12:00:00.000"],
                "SourceImage": [r"C:\a.exe"],
                "SourceProcessId": [100],
                "TargetImage": [r"C:\Windows\lsass.exe"],
                "TargetProcessId": [500],
            }
        )
        out = normalize_sysmon(raw)
        assert out["event_type"].iloc[0] == 10
        assert "lsass" in out["target_image"].iloc[0].lower()


class TestToUnified:
    def test_falcon_source(self):
        raw = pd.DataFrame({"ProcessStartTime": [1.0], "RawProcessId": [1], "ParentProcessId": [0]})
        out = to_unified(raw, "falcon")
        assert out["source"].iloc[0] == "falcon"

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="Unknown source"):
            to_unified(pd.DataFrame(), "unknown")


class TestSuspiciousMask:
    def test_detects_lsass_in_command(self):
        df = pd.DataFrame({"command_line": ["access lsass.exe", "benign"]})
        mask = suspicious_mask(df)
        assert mask.iloc[0]
        assert not mask.iloc[1]

    def test_missing_column_returns_false(self):
        df = pd.DataFrame({"other": [1]})
        mask = suspicious_mask(df)
        assert not mask.any()

    def test_custom_keywords(self):
        df = pd.DataFrame({"command_line": ["custombad"]})
        mask = suspicious_mask(df, keywords=["custombad"])
        assert mask.iloc[0]


class TestNullSummary:
    def test_counts_nulls(self):
        df = pd.DataFrame({"a": [1, None], "b": [1, 2]})
        summary = null_summary(df)
        assert summary["a"] == 1
        assert summary["b"] == 0


class TestUnifiedColumns:
    def test_expected_column_list(self):
        assert "timestamp" in UNIFIED_COLUMNS
        assert "process_image" in UNIFIED_COLUMNS
        assert len(SUSPICIOUS_KEYWORDS) >= 3
