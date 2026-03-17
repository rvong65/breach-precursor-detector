"""
Feature engineering for breach precursor detection.

Loads combined unified events, preps (clean + normalize paths), engineers 8–12
interpretable features, builds heuristic labels, runs EDA, saves parquet, and
outputs RF feature importance + top suspicious rows.
"""

import math
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier

from load_events import get_combined_events

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

REQUIRED_FOR_FEATURES = ["timestamp", "process_image", "parent_image", "pid", "ppid"]
COMPLETENESS_THRESHOLD = 0.9  # keep rows with at least this fraction of required cols non-null

SUSPICIOUS_PARENT_BASES = {
    "cmd.exe",
    "powershell.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

# (parent_base, child_base) -> score 0=ok, 1=bad (simplified; expand as needed)
UNUSUAL_CHAIN_RULES = {
    ("explorer.exe", "lsass.exe"): 1.0,
    ("explorer.exe", "lsass"): 1.0,
    ("cmd.exe", "lsass.exe"): 1.0,
    ("powershell.exe", "lsass.exe"): 1.0,
    ("powershell.exe", "mimikatz"): 1.0,
    ("cmd.exe", "procdump"): 0.9,
    ("powershell.exe", "ntdsutil.exe"): 0.9,
    ("cmd.exe", "vssadmin.exe"): 0.8,
    ("services.exe", "svchost.exe"): 0.0,
    ("svchost.exe", "conhost.exe"): 0.0,
}

HIDDEN_FLAGS = [
    "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden",
    "-enc", "-encodedcommand", "-e ",
]

LOLBAS_BASES = {
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe",
    "wmic.exe", "bitsadmin.exe", "cmstp.exe", "cscript.exe", "wscript.exe",
    "msxsl.exe", "installutil.exe", "reg.exe", "msbuild.exe", "pcalua.exe",
}

DUMP_PRECURSOR_KEYWORDS = ["lsass", "procdump", "mimikatz", "ntds", "sekurlsa", "vssadmin"]
LONG_CMD_THRESHOLD = 500

# -----------------------------------------------------------------------------
# Prep
# -----------------------------------------------------------------------------


def _base_name(path_series: pd.Series) -> pd.Series:
    """Lowercase and take last path component (backslash or forward slash)."""
    def _one(s):
        if pd.isna(s) or not str(s).strip():
            return ""
        s = str(s).strip().lower()
        return s.replace("\\", "/").split("/")[-1] if "/" in s else s
    return path_series.fillna("").astype(str).apply(_one)


def prep_events(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean and normalize for feature engineering.
    - Drop rows with < COMPLETENESS_THRESHOLD of REQUIRED_FOR_FEATURES non-null.
    - Add process_image_base, parent_image_base (lowercase basename).
    - Coerce pid/ppid to Int64 (nullable).
    """
    if df.empty:
        return df.copy()

    # Completeness: require at least 90% of required cols non-null per row
    required = [c for c in REQUIRED_FOR_FEATURES if c in df.columns]
    if not required:
        return df.copy()
    n_required = len(required)
    non_null = df[required].notna().sum(axis=1)
    keep = non_null >= (COMPLETENESS_THRESHOLD * n_required)
    out = df.loc[keep].copy()

    out["process_image_base"] = _base_name(out["process_image"])
    out["parent_image_base"] = _base_name(out["parent_image"])
    if "target_image" in out.columns:
        out["target_image_base"] = _base_name(out["target_image"])
    else:
        out["target_image_base"] = ""

    for col in ["pid", "ppid"]:
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce").astype("Int64")
    # Parquet requires consistent types: event_type is mixed int/str across sources
    if "event_type" in out.columns:
        out["event_type"] = out["event_type"].astype(str)
    return out


# -----------------------------------------------------------------------------
# Feature functions
# -----------------------------------------------------------------------------


def feat_suspicious_parent(df: pd.DataFrame) -> pd.Series:
    """Binary: parent_image_base in SUSPICIOUS_PARENT_BASES."""
    base = df.get("parent_image_base", pd.Series("", index=df.index))
    return base.str.lower().isin(SUSPICIOUS_PARENT_BASES).astype(int)


def feat_unusual_chain(df: pd.DataFrame) -> pd.Series:
    """Score 0-1 from rule table; 0.5 for unknown pairs."""
    parent = df.get("parent_image_base", pd.Series("", index=df.index)).str.lower()
    child = df.get("process_image_base", pd.Series("", index=df.index)).str.lower()
    out = pd.Series(0.5, index=df.index)
    for (p, c), score in UNUSUAL_CHAIN_RULES.items():
        mask = (parent == p) & (child == c)
        out = out.where(~mask, score)
    return out.astype(float)


def _shannon_entropy(tokens: list) -> float:
    if not tokens:
        return 0.0
    n = len(tokens)
    counts: dict[str, int] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def feat_cmd_entropy(df: pd.DataFrame) -> pd.Series:
    """Shannon entropy of command_line tokens; 0 when null."""
    cl = df.get("command_line", pd.Series("", index=df.index)).fillna("").astype(str)
    return cl.apply(lambda s: _shannon_entropy(re.split(r"\s+", s.strip()) if s.strip() else [])).astype(float)


def feat_dump_precursor(df: pd.DataFrame) -> pd.Series:
    """Binary: lsass/procdump/mimikatz/ntds in process_image, command_line, or target_image."""
    keywords = "|".join(re.escape(k) for k in DUMP_PRECURSOR_KEYWORDS)
    process = df.get("process_image", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    cl = df.get("command_line", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    target = df.get("target_image", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    if "target_image_base" in df.columns:
        tbase = df["target_image_base"].fillna("").astype(str).str.lower()
    else:
        tbase = pd.Series("", index=df.index)
    m1 = process.str.contains(keywords, regex=True, na=False)
    m2 = cl.str.contains(keywords, regex=True, na=False)
    m3 = target.str.contains(keywords, regex=True, na=False)
    m4 = tbase.str.contains("lsass", na=False)
    return (m1 | m2 | m3 | m4).astype(int)


def feat_hidden_flags(df: pd.DataFrame) -> pd.Series:
    """Count of hidden/encoding flags in command_line."""
    cl = df.get("command_line", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    out = pd.Series(0, index=df.index, dtype=int)
    for flag in HIDDEN_FLAGS:
        out += cl.str.contains(re.escape(flag), na=False).astype(int)
    return out


def feat_pid_depth(df: pd.DataFrame) -> pd.Series:
    """Process tree depth (pid -> ppid chain until root). Cap at 20."""
    pid = df["pid"].astype("Int64")
    ppid = df["ppid"].astype("Int64")
    # Map: pid -> its parent's pid (ppid)
    parent_of: dict[int, int] = {}
    for i in df.index:
        p, pp = pid.at[i], ppid.at[i]
        if pd.notna(p) and pd.notna(pp):
            parent_of[int(p)] = int(pp)
    depths = []
    for p, pp in zip(pid, ppid):
        if pd.isna(p):
            depths.append(np.nan)
            continue
        d = 0
        cur = int(p)
        seen = {cur}
        while cur in parent_of and d < 20:
            cur = parent_of[cur]
            if cur in seen:
                break
            seen.add(cur)
            d += 1
        depths.append(d)
    return pd.Series(depths, index=df.index).astype("Int64")


def feat_time_delta_parent(df: pd.DataFrame) -> pd.Series:
    """Seconds since parent event timestamp. NaN when parent not in DF."""
    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    pid = df["pid"]
    ppid = df["ppid"]
    # Index: pid -> timestamp for this process (take first if duplicate)
    pid_to_ts = df.groupby("pid")["timestamp"].min()
    pid_to_ts = pd.to_datetime(pid_to_ts, errors="coerce")
    delta = pd.Series(np.nan, index=df.index, dtype=float)
    for i in df.index:
        pp = ppid.loc[i]
        if pd.isna(pp):
            continue
        pp = int(pp)
        if pp not in pid_to_ts.index:
            continue
        parent_ts = pid_to_ts.loc[pp]
        if pd.isna(parent_ts) or pd.isna(ts.loc[i]):
            continue
        delta.loc[i] = (ts.loc[i] - parent_ts).total_seconds()
    return delta


def feat_lolbin_ratio(df: pd.DataFrame) -> pd.Series:
    """Ratio: (LOLBAS count in process + parent base) / 2. Max 1.0."""
    pbase = df.get("process_image_base", pd.Series("", index=df.index)).str.lower()
    pabase = df.get("parent_image_base", pd.Series("", index=df.index)).str.lower()
    n = (pbase.isin(LOLBAS_BASES).astype(int) + pabase.isin(LOLBAS_BASES).astype(int)) / 2.0
    return n.clip(upper=1.0).astype(float)


def feat_event_type_access(df: pd.DataFrame) -> pd.Series:
    """Binary: Sysmon event_type 10 (process access) or 8 (remote thread)."""
    et = df.get("event_type", pd.Series(None, index=df.index))
    et_num = pd.to_numeric(et, errors="coerce")
    return ((et_num == 10) | (et_num == 8)).astype(int)


def feat_has_target_lsass(df: pd.DataFrame) -> pd.Series:
    """Binary: target_image contains lsass (Sysmon 10/8)."""
    if "target_image_base" not in df.columns:
        return pd.Series(0, index=df.index)
    return df["target_image_base"].str.lower().str.contains("lsass", na=False).astype(int)


def feat_long_cmd(df: pd.DataFrame) -> pd.Series:
    """Binary: len(command_line) > LONG_CMD_THRESHOLD."""
    cl = df.get("command_line", pd.Series("", index=df.index)).fillna("").astype(str)
    return (cl.str.len() > LONG_CMD_THRESHOLD).astype(int)


def feat_rare_parent_child(df: pd.DataFrame) -> pd.Series:
    """1 - normalized count of (parent_image_base, process_image_base) pair. Higher = rarer."""
    pbase = df.get("parent_image_base", pd.Series("", index=df.index)).fillna("")
    cbase = df.get("process_image_base", pd.Series("", index=df.index)).fillna("")
    pair = pbase + "|" + cbase
    counts = pair.value_counts()
    n = len(df)
    freq = pair.map(counts).astype(float) / n if n else 0
    return (1.0 - freq).astype(float)


def build_X_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build feature matrix from prepped event DataFrame."""
    features = {
        "suspicious_parent": feat_suspicious_parent(df),
        "unusual_chain": feat_unusual_chain(df),
        "cmd_entropy": feat_cmd_entropy(df),
        "dump_precursor": feat_dump_precursor(df),
        "hidden_flags": feat_hidden_flags(df),
        "pid_depth": feat_pid_depth(df),
        "time_delta_parent": feat_time_delta_parent(df),
        "lolbin_ratio": feat_lolbin_ratio(df),
        "event_type_access": feat_event_type_access(df),
        "has_target_lsass": feat_has_target_lsass(df),
        "long_cmd": feat_long_cmd(df),
        "rare_parent_child": feat_rare_parent_child(df),
    }
    X = pd.DataFrame(features, index=df.index)
    # Keep index and timestamp for later
    X["timestamp"] = df["timestamp"].values
    return X


# -----------------------------------------------------------------------------
# Heuristic labels
# -----------------------------------------------------------------------------


def build_heuristic_labels(X: pd.DataFrame) -> pd.Series:
    """
    is_attack: 1 if dump_precursor, or top 5% by composite (suspicious_parent + dump_precursor + hidden_flags).
    """
    composite = (
        X["suspicious_parent"].fillna(0)
        + X["dump_precursor"].fillna(0)
        + X["hidden_flags"].fillna(0).clip(upper=1)  # cap so one row isn't huge
    )
    top5 = composite.quantile(0.95)
    is_attack = (X["dump_precursor"] == 1) | (composite >= top5)
    return is_attack.astype(int)


# -----------------------------------------------------------------------------
# EDA, save, RF + top rows
# -----------------------------------------------------------------------------


def run_eda(X: pd.DataFrame, y: pd.Series, output_dir: Path) -> None:
    """Correlation heatmap and feature distributions."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Numeric columns for correlation (exclude timestamp for heatmap)
    num_cols = [c for c in X.columns if c != "timestamp" and pd.api.types.is_numeric_dtype(X[c])]
    if len(num_cols) < 2:
        return
    fig, ax = plt.subplots()
    corr = X[num_cols].corr()
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="RdBu_r", center=0, ax=ax)
    fig.savefig(output_dir / "correlation_heatmap.png", bbox_inches="tight")
    plt.close(fig)

    # Distributions: histograms for numeric (sample of cols to avoid huge grid)
    for col in num_cols[:8]:
        try:
            fig, ax = plt.subplots()
            X[col].dropna().hist(bins=min(50, max(10, X[col].nunique())), ax=ax)
            ax.set_title(col)
            fig.savefig(output_dir / f"dist_{col}.png", bbox_inches="tight")
            plt.close(fig)
        except Exception:
            pass


def save_artifacts(X: pd.DataFrame, y: pd.Series, df_prep: pd.DataFrame, output_dir: Path) -> None:
    """Save X_features.parquet, y_labels.parquet, optionally events_prepped.parquet."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    X.to_parquet(output_dir / "X_features.parquet", index=True)
    pd.DataFrame({"is_attack": y}).to_parquet(output_dir / "y_labels.parquet", index=True)
    df_prep.to_parquet(output_dir / "events_prepped.parquet", index=True)


def rf_importance_and_top_suspicious(
    X: pd.DataFrame,
    y: pd.Series,
    df_prep: pd.DataFrame,
    top_n: int = 20,
    out_path: Path | None = None,
) -> None:
    """Fit RandomForest on X (target y), print feature importances and top suspicious rows."""
    num_cols = [c for c in X.columns if c != "timestamp" and pd.api.types.is_numeric_dtype(X[c])]
    Xn = X[num_cols].fillna(0)
    if y.sum() < 2 or (y == 0).sum() < 2:
        print("Not enough class variety for RF; skipping importance.")
        return
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    clf.fit(Xn, y)
    imp = pd.Series(clf.feature_importances_, index=num_cols).sort_values(ascending=False)
    print("\n--- Feature importance (RandomForest) ---")
    print(imp.to_string())

    composite = (
        X["suspicious_parent"].fillna(0) + X["dump_precursor"].fillna(0) + X["hidden_flags"].fillna(0)
    )
    top_idx = composite.nlargest(top_n).index
    show_cols = [c for c in ["timestamp", "event_type", "process_image", "parent_image", "command_line"] if c in df_prep.columns]
    feat_cols = [c for c in X.columns if c != "timestamp"]
    top_df = df_prep.loc[top_idx, show_cols].copy()
    for c in feat_cols:
        if c in X.columns:
            top_df[c] = X.loc[top_idx, c].values
    print(f"\n--- Top {top_n} suspicious rows (by composite score) ---")
    print(top_df.to_string())
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        top_df.to_csv(out_path, index=True)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Feature engineering for breach precursor detection.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="Directory with event .txt files")
    parser.add_argument("--output-dir", type=Path, default=Path("output"), help="Where to write parquet and plots")
    parser.add_argument("--chunk", type=int, default=None, help="Chunk size for Sysmon/4688 load")
    parser.add_argument("--top-n", type=int, default=20, help="Number of top suspicious rows to print")
    parser.add_argument("--no-eda", action="store_true", help="Skip EDA plots")
    args = parser.parse_args()

    print("Loading combined events...")
    df = get_combined_events(args.data_dir, chunk=args.chunk)
    if df.empty:
        print("No events loaded. Exiting.")
        return
    print(f"Loaded {len(df)} events.")

    print("Prepping (clean + normalize)...")
    df_prep = prep_events(df)
    print(f"After prep: {len(df_prep)} rows.")

    print("Building features...")
    X = build_X_features(df_prep)
    y = build_heuristic_labels(X)
    print(f"X_features shape: {X.shape}")

    save_artifacts(X, y, df_prep, args.output_dir)
    print(f"Saved parquet to {args.output_dir}")

    if not args.no_eda:
        print("Running EDA...")
        run_eda(X, y, args.output_dir)

    rf_importance_and_top_suspicious(X, y, df_prep, top_n=args.top_n, out_path=args.output_dir / "top_suspicious.csv")
    print("Done.")


if __name__ == "__main__":
    main()
