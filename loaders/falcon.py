"""CrowdStrike Falcon NDJSON event log loader."""

import json
from pathlib import Path
from typing import Iterator

import pandas as pd


def parse_falcon_line(line: str) -> dict | None:
    """Parse a single NDJSON line. Returns None on decode error."""
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def load_falcon(
    path: str | Path,
    *,
    process_creation_only: bool = False,
    chunksize: int | None = None,
    encoding: str = "utf-8",
) -> pd.DataFrame | Iterator[pd.DataFrame]:
    """
    Load CrowdStrike Falcon newline-delimited JSON into a DataFrame.

    Each line is one JSON object (ProcessRollup2 and similar events).
    Optional filter: only events with event_simpleName == "ProcessRollup2".

    Parameters
    ----------
    path : str or Path
        Path to the .txt file (NDJSON).
    process_creation_only : bool, default False
        If True, keep only rows where event_simpleName == "ProcessRollup2".
    chunksize : int, optional
        If set, yield DataFrames of up to this many rows (for streaming).
        Otherwise return a single DataFrame.
    encoding : str, default "utf-8"
        File encoding.

    Returns
    -------
    pd.DataFrame or Iterator[pd.DataFrame]
        Loaded events; columns include timestamp, event_simpleName, ImageFileName,
        ParentBaseFileName, CommandLine, RawProcessId, ParentProcessId, etc.
    """
    path = Path(path)
    if chunksize is not None:
        return _load_falcon_chunked(path, process_creation_only, chunksize, encoding)
    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            rec = parse_falcon_line(line)
            if rec is None:
                skipped += 1
                continue
            if process_creation_only and rec.get("event_simpleName") != "ProcessRollup2":
                continue
            rows.append(rec)
    if skipped:
        import warnings
        warnings.warn(f"Falcon: skipped {skipped} malformed line(s)", UserWarning)
    return pd.DataFrame(rows)


def _load_falcon_chunked(
    path: Path,
    process_creation_only: bool,
    chunksize: int,
    encoding: str,
) -> Iterator[pd.DataFrame]:
    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            rec = parse_falcon_line(line)
            if rec is None:
                skipped += 1
                continue
            if process_creation_only and rec.get("event_simpleName") != "ProcessRollup2":
                continue
            rows.append(rec)
            if len(rows) >= chunksize:
                yield pd.DataFrame(rows)
                rows = []
    if skipped:
        import warnings
        warnings.warn(f"Falcon: skipped {skipped} malformed line(s)", UserWarning)
    if rows:
        yield pd.DataFrame(rows)


