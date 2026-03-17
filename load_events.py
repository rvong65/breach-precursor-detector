"""
Load and preprocess event logs.

Loads CrowdStrike Falcon (NDJSON), Windows Security 4688 (XML), and Sysmon (XML)
into Pandas DataFrames, optionally normalizes to a unified schema, runs sanity checks,
and prints head, columns, and event-type value_counts.

Usage:
  python load_events.py [--data-dir DIR] [--no-normalize] [--chunk N]
  --data-dir    Directory containing crowdstrike_falcon.txt, 4688_windows-security.txt, windows-sysmon.txt (default: data)
  --no-normalize  Skip unified schema; print raw DataFrames only.
  --chunk N     For Sysmon (and 4688 if large), read in chunks of N lines and concatenate (default: no chunking).
"""

import argparse
from pathlib import Path

import pandas as pd

from loaders import (
    load_falcon,
    load_windows_security_4688,
    load_sysmon,
    to_unified,
    null_summary,
    suspicious_mask,
)


def _default_paths(data_dir: Path) -> tuple[Path, Path, Path]:
    return (
        data_dir / "crowdstrike_falcon.txt",
        data_dir / "4688_windows-security.txt",
        data_dir / "windows-sysmon.txt",
    )


def get_combined_events(
    data_dir: str | Path = Path("data"),
    *,
    chunk: int | None = None,
) -> pd.DataFrame:
    """
    Load all three event sources, normalize to unified schema, and return one combined DataFrame.
    Used by load_events.py and by the feature pipeline.
    """
    data_dir = Path(data_dir)
    path_falcon, path_4688, path_sysmon = _default_paths(data_dir)
    parts = []
    if path_falcon.exists():
        parts.append(to_unified(load_falcon(path_falcon), "falcon"))
    if path_4688.exists():
        df_4688 = (
            pd.concat(load_windows_security_4688(path_4688, chunksize=chunk), ignore_index=True)
            if chunk
            else load_windows_security_4688(path_4688)
        )
        parts.append(to_unified(df_4688, "security_4688"))
    if path_sysmon.exists():
        df_sysmon = (
            pd.concat(load_sysmon(path_sysmon, chunksize=chunk), ignore_index=True)
            if chunk
            else load_sysmon(path_sysmon)
        )
        parts.append(to_unified(df_sysmon, "sysmon"))
    if not parts:
        return pd.DataFrame()
    return pd.concat(parts, ignore_index=True)


def _event_type_column(df: pd.DataFrame) -> str | None:
    if "event_type" in df.columns:
        return "event_type"
    if "event_simpleName" in df.columns:
        return "event_simpleName"
    if "EventID" in df.columns:
        return "EventID"
    return None


def _inspect(df: pd.DataFrame, name: str) -> None:
    print(f"\n{'='*60}\n{name}\n{'='*60}")
    print("columns:", list(df.columns))
    print("\nhead():\n", df.head())
    col = _event_type_column(df)
    if col:
        print(f"\nvalue_counts ({col}):\n", df[col].value_counts())


def main() -> None:
    parser = argparse.ArgumentParser(description="Load breach precursor event logs into DataFrames.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="Directory with .txt event files")
    parser.add_argument("--no-normalize", action="store_true", help="Do not normalize to unified schema")
    parser.add_argument("--chunk", type=int, default=None, metavar="N", help="Chunk size for Sysmon/4688 (lines per chunk)")
    args = parser.parse_args()

    data_dir = args.data_dir
    path_falcon, path_4688, path_sysmon = _default_paths(data_dir)

    # --- Load ---
    if not path_falcon.exists():
        print(f"Warning: {path_falcon} not found; skipping Falcon.")
        df_falcon = pd.DataFrame()
    else:
        df_falcon = load_falcon(path_falcon)

    if not path_4688.exists():
        print(f"Warning: {path_4688} not found; skipping 4688.")
        df_4688 = pd.DataFrame()
    else:
        if args.chunk:
            df_4688 = pd.concat(load_windows_security_4688(path_4688, chunksize=args.chunk), ignore_index=True)
        else:
            df_4688 = load_windows_security_4688(path_4688)

    if not path_sysmon.exists():
        print(f"Warning: {path_sysmon} not found; skipping Sysmon.")
        df_sysmon = pd.DataFrame()
    else:
        if args.chunk:
            df_sysmon = pd.concat(load_sysmon(path_sysmon, chunksize=args.chunk), ignore_index=True)
        else:
            df_sysmon = load_sysmon(path_sysmon)

    # --- Optional normalize and combine ---
    normalize = not args.no_normalize
    if normalize and not df_falcon.empty:
        df_falcon_norm = to_unified(df_falcon, "falcon")
        _inspect(df_falcon_norm, "Falcon (unified)")
    elif not df_falcon.empty:
        _inspect(df_falcon, "Falcon (raw)")

    if normalize and not df_4688.empty:
        df_4688_norm = to_unified(df_4688, "security_4688")
        _inspect(df_4688_norm, "4688 Windows Security (unified)")
    elif not df_4688.empty:
        _inspect(df_4688, "4688 Windows Security (raw)")

    if normalize and not df_sysmon.empty:
        df_sysmon_norm = to_unified(df_sysmon, "sysmon")
        _inspect(df_sysmon_norm, "Sysmon (unified)")
    elif not df_sysmon.empty:
        _inspect(df_sysmon, "Sysmon (raw)")

    # --- Combined unified ---
    if normalize and (not df_falcon.empty or not df_4688.empty or not df_sysmon.empty):
        parts = []
        if not df_falcon.empty:
            parts.append(to_unified(df_falcon, "falcon"))
        if not df_4688.empty:
            parts.append(to_unified(df_4688, "security_4688"))
        if not df_sysmon.empty:
            parts.append(to_unified(df_sysmon, "sysmon"))
        combined = pd.concat(parts, ignore_index=True)
        _inspect(combined, "Combined (unified)")

        # --- Sanity checks on combined ---
        print(f"\n{'='*60}\nSanity checks (combined)\n{'='*60}")
        print("Null counts per column:\n", null_summary(combined))
        mask = suspicious_mask(combined)
        if mask.any():
            print(f"\nSuspicious command_line (keywords: lsass, procdump, rundll32, mimikatz, sekurlsa): {mask.sum()} row(s)")
            show_cols = [c for c in ["timestamp", "event_type", "process_image", "command_line"] if c in combined.columns]
            print(combined.loc[mask, show_cols].head())
        else:
            print("\nNo rows with suspicious command_line keywords in combined DataFrame.")


if __name__ == "__main__":
    main()
