"""
Confidence thresholding and basic explainability.

Loads scored_events + X_features, assigns risk_level from anomaly_score,
applies confidence gating (flag only when score < threshold AND strong indicator),
adds human-readable explanations for flagged events, evaluates vs heuristic labels,
saves gated DF and threshold config.

For feature-level importance per event, SHAP TreeExplainer is used in explainability.py
(wired from this module when --model-path is present).
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


# -----------------------------------------------------------------------------
# Risk level bounds (percentile-based; lower score = more anomalous)
# -----------------------------------------------------------------------------

DEFAULT_RISK_PERCENTILES = {
    "Critical": 0.02,   # score <= 2nd percentile
    "High": 0.05,       # score <= 5th
    "Medium": 0.10,     # score <= 10th
    "Low": 0.20,        # score <= 20th
    # else Normal
}


def load_data(
    scored_path: Path,
    x_path: Path,
    y_path: Path | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series | None]:
    """Load scored_events, X_features, optional y_labels. Returns (scored, X, y)."""
    scored = pd.read_parquet(scored_path)
    X = pd.read_parquet(x_path)
    y = None
    if y_path and y_path.exists():
        y_df = pd.read_parquet(y_path)
        if "is_attack" in y_df.columns:
            y = y_df["is_attack"]
        elif len(y_df.columns) == 1:
            y = y_df.iloc[:, 0]
    return scored, X, y


def merge_scored_and_features(scored: pd.DataFrame, X: pd.DataFrame) -> pd.DataFrame:
    """Merge on index; scored columns take precedence for overlap (e.g. timestamp)."""
    # Drop timestamp from X if present to avoid duplicate; keep feature cols only
    feature_cols = [c for c in X.columns if c != "timestamp" and pd.api.types.is_numeric_dtype(X[c])]
    df = scored.join(X[feature_cols], how="left", rsuffix="_feat")
    # Remove any _feat duplicates (shouldn't be any if we only took feature_cols)
    df = df.loc[:, ~df.columns.duplicated()]
    return df


def add_risk_level(
    df: pd.DataFrame,
    score_col: str = "anomaly_score",
    percentiles: dict[str, float] | None = None,
) -> pd.DataFrame:
    """Add risk_level: Critical, High, Medium, Low, Normal from percentile cutoffs."""
    percentiles = percentiles or DEFAULT_RISK_PERCENTILES
    s = df[score_col]
    thresholds = {}
    for level, p in percentiles.items():
        thresholds[level] = s.quantile(p)
    # Critical <= 2%, High <= 5%, Medium <= 10%, Low <= 20%, else Normal
    def _level(score):
        if pd.isna(score):
            return "Normal"
        if score <= thresholds.get("Critical", float("-inf")):
            return "Critical"
        if score <= thresholds.get("High", float("-inf")):
            return "High"
        if score <= thresholds.get("Medium", float("-inf")):
            return "Medium"
        if score <= thresholds.get("Low", float("-inf")):
            return "Low"
        return "Normal"
    df = df.copy()
    df["risk_level"] = s.apply(_level)
    return df


def strong_indicator(df: pd.DataFrame) -> pd.Series:
    """True when (suspicious_parent==1) OR (dump_precursor==1) OR (hidden_flags>=2)."""
    sp = df.get("suspicious_parent", pd.Series(0, index=df.index)).fillna(0)
    dp = df.get("dump_precursor", pd.Series(0, index=df.index)).fillna(0)
    hf = df.get("hidden_flags", pd.Series(0, index=df.index)).fillna(0)
    return ((sp == 1) | (dp == 1) | (hf >= 2)).astype(bool)


def add_flagged(
    df: pd.DataFrame,
    score_threshold: float | None = None,
    score_col: str = "anomaly_score",
) -> tuple[pd.DataFrame, float]:
    """Set flagged = (anomaly_score < threshold) AND strong_indicator. Returns (df, threshold_used)."""
    df = df.copy()
    strong = strong_indicator(df)
    s = df[score_col]
    if score_threshold is None:
        score_threshold = float(s.quantile(0.05))
    df["flagged"] = (s < score_threshold) & strong
    return df, score_threshold


def _explanation_one_row(row: pd.Series, score: float) -> str:
    """Build 1-3 reason strings for a flagged row (SOC-friendly)."""
    reasons = []
    process = (row.get("process_image") or "").lower()
    parent = (row.get("parent_image") or "").lower()
    cmd = (row.get("command_line") or "").lower()

    if "lsass" in process or "lsass" in cmd or "lsass" in (row.get("target_image") or "").lower():
        reasons.append("lsass access")
    if "vssadmin" in process or "vssadmin" in cmd or "shadow" in cmd:
        reasons.append("vssadmin shadow copy pattern")
    if "ntdsutil" in process or "ntdsutil" in cmd or "ntds" in cmd:
        reasons.append("ntdsutil/ntds credential pattern")
    if "procdump" in process or "procdump" in cmd:
        reasons.append("procdump-style access")
    if "mimikatz" in process or "mimikatz" in cmd:
        reasons.append("mimikatz-style activity")

    if not reasons and row.get("dump_precursor") == 1:
        reasons.append("credential dump precursor")

    if "encodedcommand" in cmd or "-enc " in cmd or "encodedcommand" in cmd:
        reasons.append("encoded PowerShell command line")
    if row.get("hidden_flags", 0) >= 2:
        if "encoded" not in " ".join(reasons).lower():
            reasons.append("hidden/encoding flags in command line")

    if row.get("unusual_chain", 0.5) > 0.7:
        reasons.append("unusual parent-child chain")
    if row.get("cmd_entropy", 0) > 2.5:
        reasons.append("high command entropy")
    if row.get("long_cmd") == 1 and "encoded" not in " ".join(reasons).lower():
        reasons.append("long/obfuscated command line")

    if row.get("suspicious_parent") == 1 and not any("suspicious" in r or "parent" in r for r in reasons):
        reasons.append("suspicious parent (cmd/powershell/wmic)")

    reasons = reasons[:3]
    if not reasons:
        reasons = ["anomalous process behavior"]
    score_str = f"{score:.3f}" if not np.isnan(score) else "N/A"
    return "Flagged: " + " + ".join(reasons) + f" (score: {score_str})"


def add_explanations(df: pd.DataFrame, score_col: str = "anomaly_score") -> pd.DataFrame:
    """Add explanation column: human-readable string for flagged rows, else '—'."""
    df = df.copy()
    expl = []
    for i in df.index:
        row = df.loc[i]
        if row.get("flagged", False):
            expl.append(_explanation_one_row(row, row[score_col]))
        else:
            expl.append("—")
    df["explanation"] = expl
    return df


def evaluate_gated(
    df: pd.DataFrame,
    y_true: pd.Series | None,
    output_dir: Path,
    top_n: int = 20,
) -> None:
    """Precision/recall/F1 vs is_attack; top N flagged with explanation; sanity check."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    pred = df["flagged"].astype(int)

    if y_true is not None and df.index.isin(y_true.index).any():
        y = y_true.reindex(df.index).fillna(0).astype(int)
        p = precision_score(y, pred, zero_division=0)
        r = recall_score(y, pred, zero_division=0)
        f1 = f1_score(y, pred, zero_division=0)
        print("\n--- After gating (flagged vs is_attack) ---")
        print(f"  Precision: {p:.4f}  Recall: {r:.4f}  F1: {f1:.4f}")
        cm = confusion_matrix(y, pred)
        print("  Confusion matrix (rows=true, cols=pred):")
        print("    ", cm)

    flagged_df = df[df["flagged"]].sort_values("anomaly_score").head(top_n)
    show_cols = [c for c in ["timestamp", "process_image", "parent_image", "command_line", "anomaly_score", "risk_level", "explanation"] if c in df.columns]
    if not flagged_df.empty and show_cols:
        print(f"\n--- Top {top_n} flagged events ---")
        print(flagged_df[show_cols].to_string())
        flagged_df[show_cols].to_csv(output_dir / "top_flagged_gated.csv", index=True)

    # Sanity check: vssadmin, lsass, ntdsutil in flagged set
    key_patterns = ["vssadmin", "lsass", "ntdsutil"]
    cmd = df.get("command_line", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    process = df.get("process_image", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    flagged_idx = df[df["flagged"]].index
    print("\n--- Sanity check (key patterns in flagged set) ---")
    for pat in key_patterns:
        in_cmd = (cmd.loc[flagged_idx].str.contains(pat, na=False)).sum()
        in_process = (process.loc[flagged_idx].str.contains(pat, na=False)).sum()
        total = in_cmd + in_process
        print(f"  {pat}: {total} flagged row(s) contain it")
        if total == 0 and len(flagged_idx) > 0:
            print(f"    Warning: no flagged row contains '{pat}' — check threshold or strong_indicator.")


def save_config(
    output_dir: Path,
    score_threshold: float,
    risk_percentiles: dict[str, float],
    *,
    shap_enabled: bool = False,
) -> None:
    """Write threshold_config.json."""
    config = {
        "score_threshold": score_threshold,
        "risk_level_bounds": risk_percentiles,
        "strong_indicator_definition": "suspicious_parent == 1 OR dump_precursor == 1 OR hidden_flags >= 2",
        "shap_enabled": shap_enabled,
    }
    path = Path(output_dir) / "threshold_config.json"
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"\nSaved threshold config to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Confidence gating and explainability.")
    parser.add_argument("--scored-path", type=Path, default=Path("output/scored_events.parquet"))
    parser.add_argument("--x-path", type=Path, default=Path("output/X_features.parquet"))
    parser.add_argument("--y-path", type=Path, default=Path("output/y_labels.parquet"))
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--score-threshold", type=float, default=None, help="Fixed threshold; if omitted, use 5th percentile")
    parser.add_argument("--top-n", type=int, default=20)
    parser.add_argument(
        "--model-path",
        type=Path,
        default=Path("output/isolation_forest_model.pkl"),
        help="Isolation Forest model for optional SHAP feature attribution",
    )
    parser.add_argument(
        "--no-shap",
        action="store_true",
        help="Skip SHAP feature attribution even if model exists",
    )
    args = parser.parse_args()

    print("Loading scored events and features...")
    scored, X, y_true = load_data(args.scored_path, args.x_path, args.y_path)
    if scored.empty or X.empty:
        print("Missing scored or X data. Exiting.")
        return

    df = merge_scored_and_features(scored, X)
    print("Merged shape:", df.shape)

    df = add_risk_level(df)
    df, score_threshold = add_flagged(df, score_threshold=args.score_threshold)
    df = add_explanations(df)

    shap_enabled = False
    if not args.no_shap and args.model_path.exists():
        from explainability import append_shap_to_explanations

        before = df.loc[df["flagged"], "explanation"].head(1).tolist() if df["flagged"].any() else []
        df = append_shap_to_explanations(df, args.model_path)
        after = df.loc[df["flagged"], "explanation"].head(1).tolist() if df["flagged"].any() else []
        shap_enabled = before != after or any(
            "Top features:" in str(e) for e in df.loc[df["flagged"], "explanation"]
        )
        if shap_enabled:
            print("SHAP feature attribution appended to flagged explanations.")
    elif not args.no_shap:
        print(f"SHAP skipped: model not found at {args.model_path}")

    print("\n--- Threshold choices ---")
    print(f"  Score threshold (gating): {score_threshold:.4f}")
    print(f"  Risk level bounds (percentiles): {DEFAULT_RISK_PERCENTILES}")

    evaluate_gated(df, y_true, args.output_dir, top_n=args.top_n)
    save_config(args.output_dir, score_threshold, DEFAULT_RISK_PERCENTILES, shap_enabled=shap_enabled)

    out_path = args.output_dir / "scored_events_gated.parquet"
    df.to_parquet(out_path, index=True)
    print(f"\nSaved gated events to {out_path}")
    print("Done.")


if __name__ == "__main__":
    main()
