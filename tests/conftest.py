"""Shared fixtures for offline unit and integration tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import pandas as pd
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def base_ts() -> datetime:
    return datetime(2024, 6, 1, 10, 0, 0)


@pytest.fixture
def minimal_events(base_ts: datetime) -> pd.DataFrame:
    """Minimal event DataFrame for feature engineering (pre-unified schema)."""
    return pd.DataFrame(
        {
            "timestamp": [
                base_ts,
                base_ts + timedelta(seconds=1),
                base_ts + timedelta(seconds=2),
                base_ts + timedelta(seconds=3),
            ],
            "process_image": [
                "C:/Windows/System32/lsass.exe",
                "C:/Windows/System32/procdump.exe",
                "C:/Windows/System32/cmd.exe",
                "C:/Windows/explorer.exe",
            ],
            "parent_image": [
                "C:/Windows/System32/cmd.exe",
                "C:/Windows/System32/powershell.exe",
                "C:/Windows/System32/services.exe",
                "C:/Windows/System32/services.exe",
            ],
            "command_line": [
                "vssadmin create shadow /all",
                "procdump -ma lsass.exe dump.dmp",
                "powershell -nop -w hidden -enc ABC",
                "normal benign process",
            ],
            "pid": [100, 101, 102, 103],
            "ppid": [50, 50, 4, 4],
            "event_type": ["1", "1", "1", "4688"],
            "target_image": [None, "C:/Windows/System32/lsass.exe", None, None],
        }
    )


@pytest.fixture
def scored_merge_df() -> pd.DataFrame:
    """Scored events merged with feature columns for gating tests."""
    n = 20
    scores = [float(i) for i in range(n)]
    return pd.DataFrame(
        {
            "anomaly_score": scores,
            "process_image": ["cmd.exe"] * n,
            "parent_image": ["explorer.exe"] * n,
            "command_line": ["whoami"] * n,
            "suspicious_parent": [0, 1, 0, 1, 0] * 4,
            "dump_precursor": [0, 0, 1, 0, 0] * 4,
            "hidden_flags": [0, 0, 0, 2, 0] * 4,
            "unusual_chain": [0.5] * n,
            "cmd_entropy": [1.0] * n,
            "long_cmd": [0] * n,
        }
    )
