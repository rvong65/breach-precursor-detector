"""Windows Security Event ID 4688 (process creation) XML loader."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

import pandas as pd

# Windows Event schema namespace (one <Event> per line).
NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_hex_id(value: str | None) -> int | None:
    if value is None or not str(value).strip():
        return None
    s = str(value).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return None


def parse_4688_line(line: str) -> dict | None:
    """
    Parse a single line containing one <Event> XML (4688).
    Returns a dict with system_time, NewProcessId, NewProcessName, ProcessId, CommandLine, ParentProcessName.
    """
    line = line.strip()
    if not line:
        return None
    try:
        root = ET.fromstring(line)
    except ET.ParseError:
        return None

    time_created = root.find(".//ev:TimeCreated", NS)
    system_time = time_created.get("SystemTime") if time_created is not None else None
    event_id_elem = root.find(".//ev:EventID", NS)
    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else None

    data = {}
    for d in root.findall(".//ev:Data", NS):
        name = d.get("Name")
        if name:
            data[name] = d.text

    row = {
        "system_time": system_time,
        "EventID": event_id,
        "NewProcessId": data.get("NewProcessId"),
        "NewProcessName": data.get("NewProcessName"),
        "ProcessId": data.get("ProcessId"),
        "CommandLine": data.get("CommandLine"),
        "ParentProcessName": data.get("ParentProcessName"),
    }
    # Optionally convert hex IDs here; normalizer will do it too. Keep as string for raw DF.
    return row


def load_windows_security_4688(
    path: str | Path,
    *,
    chunksize: int | None = None,
    encoding: str = "utf-8",
) -> pd.DataFrame | Iterator[pd.DataFrame]:
    """
    Load Windows Security 4688 events (one <Event> per line) into a DataFrame.

    Parameters
    ----------
    path : str or Path
        Path to the .txt file.
    chunksize : int, optional
        If set, yield DataFrames of up to this many rows.
    encoding : str, default "utf-8"
        File encoding.

    Returns
    -------
    pd.DataFrame or Iterator[pd.DataFrame]
        Columns: system_time, EventID, NewProcessId, NewProcessName, ProcessId, CommandLine, ParentProcessName.
    """
    path = Path(path)
    if chunksize is not None:
        return _load_4688_chunked(path, chunksize, encoding)

    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            row = parse_4688_line(line)
            if row is None:
                skipped += 1
                continue
            rows.append(row)

    if skipped:
        import warnings
        warnings.warn(f"4688: skipped {skipped} malformed line(s)", UserWarning)
    return pd.DataFrame(rows)


def _load_4688_chunked(
    path: Path,
    chunksize: int,
    encoding: str,
) -> Iterator[pd.DataFrame]:
    rows: list[dict] = []
    skipped = 0
    with open(path, encoding=encoding) as f:
        for line in f:
            row = parse_4688_line(line)
            if row is None:
                skipped += 1
                continue
            rows.append(row)
            if len(rows) >= chunksize:
                yield pd.DataFrame(rows)
                rows = []
    if skipped:
        import warnings
        warnings.warn(f"4688: skipped {skipped} malformed line(s)", UserWarning)
    if rows:
        yield pd.DataFrame(rows)
