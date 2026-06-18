"""Tests for feature_engineering.py — prep, features, labels."""

from __future__ import annotations

import pandas as pd
import pytest

from feature_engineering import (
    build_X_features,
    build_heuristic_labels,
    feat_cmd_entropy,
    feat_dump_precursor,
    feat_hidden_flags,
    feat_long_cmd,
    feat_lolbin_ratio,
    feat_suspicious_parent,
    feat_unusual_chain,
    prep_events,
)


class TestPrepEvents:
    def test_empty_returns_empty(self):
        assert prep_events(pd.DataFrame()).empty

    def test_adds_base_columns(self, minimal_events):
        out = prep_events(minimal_events)
        assert "process_image_base" in out.columns
        assert "parent_image_base" in out.columns

    def test_drops_incomplete_rows(self, minimal_events):
        bad = minimal_events.copy()
        bad.loc[0, "pid"] = None
        bad.loc[0, "ppid"] = None
        bad.loc[0, "parent_image"] = None
        out = prep_events(bad)
        assert len(out) <= len(bad)

    def test_pid_ppid_coerced_to_int64(self, minimal_events):
        out = prep_events(minimal_events)
        assert str(out["pid"].dtype) == "Int64"


class TestFeatSuspiciousParent:
    def test_cmd_parent_is_suspicious(self, minimal_events):
        prepped = prep_events(minimal_events)
        result = feat_suspicious_parent(prepped)
        assert result.iloc[0] == 1

    def test_services_parent_not_suspicious(self, minimal_events):
        prepped = prep_events(minimal_events)
        result = feat_suspicious_parent(prepped)
        assert result.iloc[3] == 0


class TestFeatUnusualChain:
    def test_cmd_to_lsass_high_score(self, minimal_events):
        prepped = prep_events(minimal_events)
        result = feat_unusual_chain(prepped)
        assert result.iloc[0] == 1.0

    def test_unknown_pair_default_half(self, minimal_events):
        prepped = prep_events(minimal_events)
        result = feat_unusual_chain(prepped)
        assert result.iloc[3] == 0.5


class TestFeatCmdEntropy:
    def test_empty_command_zero_entropy(self):
        df = pd.DataFrame({"command_line": [""]})
        assert feat_cmd_entropy(df).iloc[0] == 0.0

    def test_repeated_tokens_lower_entropy(self):
        df = pd.DataFrame({"command_line": ["a a a a", "a b c d e f g h"]})
        ent = feat_cmd_entropy(df)
        assert ent.iloc[0] < ent.iloc[1]


class TestFeatDumpPrecursor:
    def test_vssadmin_in_command(self, minimal_events):
        prepped = prep_events(minimal_events)
        assert feat_dump_precursor(prepped).iloc[0] == 1

    def test_procdump_in_process(self, minimal_events):
        prepped = prep_events(minimal_events)
        assert feat_dump_precursor(prepped).iloc[1] == 1

    def test_benign_process_zero(self, minimal_events):
        prepped = prep_events(minimal_events)
        assert feat_dump_precursor(prepped).iloc[3] == 0


class TestFeatHiddenFlags:
    def test_counts_encoding_flags(self, minimal_events):
        prepped = prep_events(minimal_events)
        assert feat_hidden_flags(prepped).iloc[2] >= 2

    def test_no_flags_on_benign(self, minimal_events):
        prepped = prep_events(minimal_events)
        assert feat_hidden_flags(prepped).iloc[3] == 0


class TestFeatLolbinRatio:
    def test_lolbin_parent_and_child(self, minimal_events):
        prepped = prep_events(minimal_events)
        ratio = feat_lolbin_ratio(prepped)
        assert ratio.max() <= 1.0
        assert ratio.min() >= 0.0


class TestFeatLongCmd:
    def test_short_command_not_long(self):
        df = pd.DataFrame({"command_line": ["short"]})
        assert feat_long_cmd(df).iloc[0] == 0

    def test_very_long_command(self):
        df = pd.DataFrame({"command_line": ["x" * 600]})
        assert feat_long_cmd(df).iloc[0] == 1


class TestBuildXFeatures:
    def test_twelve_feature_columns(self, minimal_events):
        prepped = prep_events(minimal_events)
        X = build_X_features(prepped)
        feature_cols = [c for c in X.columns if c != "timestamp"]
        assert len(feature_cols) == 12

    def test_index_preserved(self, minimal_events):
        prepped = prep_events(minimal_events)
        X = build_X_features(prepped)
        assert len(X) == len(prepped)


class TestBuildHeuristicLabels:
    def test_dump_precursor_always_attack(self, minimal_events):
        prepped = prep_events(minimal_events)
        X = build_X_features(prepped)
        labels = build_heuristic_labels(X)
        dump_rows = X["dump_precursor"] == 1
        assert labels[dump_rows].eq(1).all()

    def test_labels_are_binary(self, minimal_events):
        prepped = prep_events(minimal_events)
        X = build_X_features(prepped)
        labels = build_heuristic_labels(X)
        assert set(labels.unique()) <= {0, 1}
