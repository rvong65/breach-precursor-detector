"""Sysmon XML event log loader (EventID 1 process create, 8 remote thread, 10 process access)."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

import pandas as pd

NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

def parse_sysmon_line(line: str) -> dict | None:
    """
    Parse one line containing one Sysmon <Event>.
    Returns dict with EventID, TimeCreated, UtcTime, and all EventData fields (Image, ParentImage,
    ProcessId, CommandLine for ID 1; SourceImage, TargetImage, SourceProcessId, TargetProcessId for ID 10/8).
    """
    line = line.strip()
    if not line:
        return None
    try:
        root = ET.fromstring(line)
    except ET.ParseError:
        return None

    event_id_elem = root.find(".//ev:EventID", NS)
    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else None
    time_created = root.find(".//ev:TimeCreated", NS)
    system_time = time_created.get("SystemTime") if time_created is not None else None

    data = {}
    for d in root.findall(".//ev:Data", NS):
        name = d.get("Name")
        if name:
            data[name] = d.text

    row = {"EventID": event_id, "TimeCreated": system_time, **data}
    if "UtcTime" not in row and "UtcTime" in data:
        row["UtcTime"] = data["UtcTime"]
    return row


def load_sysmon(
    path: str | Path,
    *,
    event_ids: list[int] | None = None,
    chunksize: int | None = None,
    encoding: str = "utf-8",
) -> pd.DataFrame | Iterator[pd.DataFrame]:
    """
    Load Sysmon events (one <Event> per line) into a DataFrame.

    Parameters
    ----------
    path : str or Path
        Path to the .txt file.
    event_ids : list of int, optional
        If set, keep only these EventIDs (e.g. [1] for process creation only, [1, 8, 10] for all).
    chunksize : int, optional
        If set, yield DataFrames of up to this many rows (for large files).
    encoding : str, default "utf-8"
        File encoding.

    Returns
    -------
    pd.DataFrame or Iterator[pd.DataFrame]
        Columns include EventID, UtcTime, TimeCreated, Image, ParentImage, ProcessId,
        ParentProcessId, CommandLine, SourceImage, SourceProcessId, TargetImage, TargetProcessId, etc.
    """
    path = Path(path)
    if chunksize is not None:
        return _load_sysmon_chunked(path, event_ids, chunksize, encoding)

    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            row = parse_sysmon_line(line)
            if row is None:
                skipped += 1
                continue
            if event_ids is not None and row.get("EventID") not in event_ids:
                continue
            rows.append(row)

    if skipped:
        import warnings
        warnings.warn(f"Sysmon: skipped {skipped} malformed line(s)", UserWarning)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def _load_sysmon_chunked(
    path: Path,
    event_ids: list[int] | None,
    chunksize: int,
    encoding: str,
) -> Iterator[pd.DataFrame]:
    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            row = parse_sysmon_line(line)
            if row is None:
                skipped += 1
                continue
            if event_ids is not None and row.get("EventID") not in event_ids:
                continue
            rows.append(row)
            if len(rows) >= chunksize:
                yield pd.DataFrame(rows)
                rows = []
    if skipped:
        import warnings
        warnings.warn(f"Sysmon: skipped {skipped} malformed line(s)", UserWarning)
    if rows:
        yield pd.DataFrame(rows)
