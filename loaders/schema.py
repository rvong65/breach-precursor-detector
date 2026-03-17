"""Unified schema and normalizers for process event DataFrames."""

from typing import Literal

import pandas as pd

# Common columns for process-centric analysis (and later anomaly detection).
UNIFIED_COLUMNS = [
    "timestamp",
    "event_type",
    "process_image",
    "parent_image",
    "command_line",
    "pid",
    "ppid",
    "source",
]
# Optional for Sysmon 10/8: target_image, target_pid
OPTIONAL_UNIFIED = ["target_image", "target_pid"]


def _parse_hex_id(value: str | None) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return None


def normalize_falcon(df: pd.DataFrame) -> pd.DataFrame:
    """Map Falcon raw columns to unified schema. Converts timestamp and pid/ppid."""
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_COLUMNS + OPTIONAL_UNIFIED)

    # Prefer ProcessStartTime (Unix float seconds), else timestamp (ms)
    ts = df.get("ProcessStartTime")
    if ts is None or ts.isna().all():
        ts = df.get("timestamp")
        if ts is not None:
            ts = pd.to_numeric(ts, errors="coerce") / 1000.0  # ms -> seconds
    else:
        # ProcessStartTime can be string from JSON (e.g. "1658910730.111"); must be numeric for unit="s"
        ts = pd.to_numeric(ts, errors="coerce")
    if ts is not None:
        timestamp = pd.to_datetime(ts, unit="s")
    else:
        timestamp = pd.NaT

    out = pd.DataFrame(
        {
            "timestamp": timestamp,
            "event_type": df.get("event_simpleName"),
            "process_image": df.get("ImageFileName"),
            "parent_image": df.get("ParentBaseFileName"),
            "command_line": df.get("CommandLine"),
            "pid": pd.to_numeric(df.get("RawProcessId"), errors="coerce"),
            "ppid": pd.to_numeric(df.get("ParentProcessId"), errors="coerce"),
            "source": "falcon",
        }
    )
    for col in OPTIONAL_UNIFIED:
        out[col] = None
    return out


def normalize_4688(df: pd.DataFrame) -> pd.DataFrame:
    """Map Windows Security 4688 raw columns to unified schema."""
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_COLUMNS + OPTIONAL_UNIFIED)

    # Loader will provide: system_time, NewProcessId, NewProcessName, ProcessId, CommandLine, ParentProcessName
    timestamp = pd.to_datetime(df.get("system_time"), errors="coerce")
    pid = df.get("NewProcessId")
    if pid is not None:
        pid = pid.apply(_parse_hex_id)
    ppid = df.get("ProcessId")
    if ppid is not None:
        ppid = ppid.apply(_parse_hex_id)

    out = pd.DataFrame(
        {
            "timestamp": timestamp,
            "event_type": "4688",
            "process_image": df.get("NewProcessName"),
            "parent_image": df.get("ParentProcessName"),
            "command_line": df.get("CommandLine"),
            "pid": pid,
            "ppid": ppid,
            "source": "security_4688",
        }
    )
    for col in OPTIONAL_UNIFIED:
        out[col] = None
    return out


def normalize_sysmon(df: pd.DataFrame) -> pd.DataFrame:
    """Map Sysmon raw columns to unified schema. Handles EventID 1, 8, 10."""
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_COLUMNS + OPTIONAL_UNIFIED)

    event_id = df.get("EventID")
    timestamp = pd.to_datetime(df.get("UtcTime"), format="mixed", errors="coerce")
    if timestamp.isna().all() and "TimeCreated" in df.columns:
        timestamp = pd.to_datetime(df["TimeCreated"], errors="coerce")

    # EventID 1: process create -> Image, ParentImage, ProcessId, ParentProcessId, CommandLine
    # EventID 10/8: SourceImage, SourceProcessId, TargetImage, TargetProcessId
    process_image = df.get("Image").fillna(df.get("SourceImage"))
    parent_image = df.get("ParentImage")  # only for event 1
    command_line = df.get("CommandLine")
    pid = pd.to_numeric(df.get("ProcessId"), errors="coerce").fillna(
        pd.to_numeric(df.get("SourceProcessId"), errors="coerce")
    )
    ppid = pd.to_numeric(df.get("ParentProcessId"), errors="coerce")
    target_image = df.get("TargetImage")
    target_pid = pd.to_numeric(df.get("TargetProcessId"), errors="coerce")

    out = pd.DataFrame(
        {
            "timestamp": timestamp,
            "event_type": event_id,
            "process_image": process_image,
            "parent_image": parent_image,
            "command_line": command_line,
            "pid": pid,
            "ppid": ppid,
            "source": "sysmon",
            "target_image": target_image,
            "target_pid": target_pid,
        }
    )
    return out


def to_unified(
    df: pd.DataFrame,
    source: Literal["falcon", "security_4688", "sysmon"],
) -> pd.DataFrame:
    """
    Normalize a raw loader DataFrame to the unified schema.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame from load_falcon, load_windows_security_4688, or load_sysmon.
    source : 'falcon' | 'security_4688' | 'sysmon'
        Which loader produced the data (selects normalizer).

    Returns
    -------
    pd.DataFrame
        DataFrame with columns from UNIFIED_COLUMNS (+ optional target_* for Sysmon).
    """
    if source == "falcon":
        return normalize_falcon(df)
    if source == "security_4688":
        return normalize_4688(df)
    if source == "sysmon":
        return normalize_sysmon(df)
    raise ValueError(f"Unknown source: {source!r}")


# --- Sanity checks ---

SUSPICIOUS_KEYWORDS = ["lsass", "procdump", "rundll32", "mimikatz", "sekurlsa"]


def suspicious_mask(
    df: pd.DataFrame,
    column: str = "command_line",
    keywords: list[str] | None = None,
) -> pd.Series:
    """
    Boolean mask of rows whose command_line (or given column) contains any suspicious keyword.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame with a command_line-like column.
    column : str, default "command_line"
        Column name to search.
    keywords : list of str, optional
        Substrings to match (case-insensitive). Default: lsass, procdump, rundll32, mimikatz, sekurlsa.

    Returns
    -------
    pd.Series
        Boolean series, True where any keyword appears.
    """
    if column not in df.columns:
        return pd.Series(False, index=df.index)
    keywords = keywords or SUSPICIOUS_KEYWORDS
    cl = df[column].fillna("").astype(str).str.lower()
    pattern = "|".join(keywords)
    return cl.str.contains(pattern, case=False, na=False)


def null_summary(df: pd.DataFrame) -> pd.Series:
    """Return count of nulls per column (df.isnull().sum())."""
    return df.isnull().sum()
