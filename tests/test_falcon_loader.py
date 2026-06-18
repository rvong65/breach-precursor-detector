"""Tests for loaders/falcon.py — NDJSON parsing."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from loaders.falcon import load_falcon, parse_falcon_line


class TestParseFalconLine:
    def test_valid_json(self):
        line = '{"event_simpleName": "ProcessRollup2", "RawProcessId": 100}'
        rec = parse_falcon_line(line)
        assert rec["RawProcessId"] == 100

    def test_empty_line_returns_none(self):
        assert parse_falcon_line("") is None
        assert parse_falcon_line("   ") is None

    def test_malformed_json_returns_none(self):
        assert parse_falcon_line("{not json") is None


class TestLoadFalcon:
    def test_loads_fixture_file(self, tmp_path: Path):
        path = tmp_path / "falcon.txt"
        path.write_text(
            '{"event_simpleName": "ProcessRollup2", "ImageFileName": "cmd.exe", "RawProcessId": 1, "ParentProcessId": 0}\n'
            '{"event_simpleName": "OtherEvent", "ImageFileName": "x.exe"}\n',
            encoding="utf-8",
        )
        df = load_falcon(path)
        assert len(df) == 2

    def test_process_creation_filter(self, tmp_path: Path):
        path = tmp_path / "falcon.txt"
        path.write_text(
            '{"event_simpleName": "ProcessRollup2", "RawProcessId": 1}\n'
            '{"event_simpleName": "OtherEvent", "RawProcessId": 2}\n',
            encoding="utf-8",
        )
        df = load_falcon(path, process_creation_only=True)
        assert len(df) == 1
        assert df.iloc[0]["event_simpleName"] == "ProcessRollup2"

    def test_skips_malformed_lines(self, tmp_path: Path):
        path = tmp_path / "falcon.txt"
        path.write_text('{"RawProcessId": 1}\n{broken\n{"RawProcessId": 2}\n', encoding="utf-8")
        with pytest.warns(UserWarning, match="skipped"):
            df = load_falcon(path)
        assert len(df) == 2
