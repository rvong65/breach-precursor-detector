"""
SHAP-based feature attribution for flagged anomaly events.

Computes top contributing features via TreeExplainer on the saved Isolation Forest.
Used at batch time in confidence_gating (not in Streamlit request path).
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def feature_matrix_from_df(df: pd.DataFrame) -> pd.DataFrame:
    """Numeric feature columns only; fill NaN with 0 (matches train_isolation_forest.prepare_X_train)."""
    numeric_cols = [c for c in df.columns if c != "timestamp" and pd.api.types.is_numeric_dtype(df[c])]
    return df[numeric_cols].fillna(0)


def load_model(model_path: Path) -> IsolationForest | None:
    """Load serialized Isolation Forest; return None if missing."""
    path = Path(model_path)
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def format_top_shap_features(
    shap_row: np.ndarray,
    feature_names: list[str],
    top_k: int = 3,
) -> str:
    """Format top-|SHAP| features as a short SOC-friendly suffix."""
    if shap_row is None or len(shap_row) == 0 or not feature_names:
        return ""
    arr = np.asarray(shap_row, dtype=float).flatten()
    if arr.size != len(feature_names):
        return ""
    order = np.argsort(-np.abs(arr))[:top_k]
    parts = []
    for idx in order:
        val = arr[idx]
        if np.isnan(val) or abs(val) < 1e-9:
            continue
        sign = "+" if val >= 0 else ""
        parts.append(f"{feature_names[idx]} ({sign}{val:.2f})")
    if not parts:
        return ""
    return " | Top features: " + ", ".join(parts)


def compute_shap_suffixes(
    model: IsolationForest,
    df: pd.DataFrame,
    indices: pd.Index,
    *,
    top_k: int = 3,
) -> dict[object, str]:
    """
    SHAP TreeExplainer for flagged row indices only.
    Returns {index: suffix string} to append to rule-based explanations.
    """
    import shap

    if len(indices) == 0:
        return {}

    X = feature_matrix_from_df(df)
    feature_names = list(X.columns)
    X_flagged = X.loc[indices]

    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_flagged)
    except Exception:
        return {}

    # IsolationForest may return ndarray or list of ndarrays
    if isinstance(shap_values, list):
        shap_values = shap_values[0] if shap_values else np.array([])

    shap_values = np.asarray(shap_values)
    if shap_values.ndim == 1:
        shap_values = shap_values.reshape(1, -1)

    out: dict[object, str] = {}
    for i, idx in enumerate(indices):
        if i >= len(shap_values):
            break
        suffix = format_top_shap_features(shap_values[i], feature_names, top_k=top_k)
        if suffix:
            out[idx] = suffix
    return out


def append_shap_to_explanations(
    df: pd.DataFrame,
    model_path: Path,
    *,
    top_k: int = 3,
) -> pd.DataFrame:
    """Append SHAP suffix to explanation column for flagged rows when model is available."""
    df = df.copy()
    if "explanation" not in df.columns or "flagged" not in df.columns:
        return df

    model = load_model(model_path)
    if model is None:
        return df

    flagged_idx = df.index[df["flagged"].fillna(False)]
    suffixes = compute_shap_suffixes(model, df, flagged_idx, top_k=top_k)

    for idx, suffix in suffixes.items():
        if idx in df.index and df.at[idx, "explanation"] != "—":
            df.at[idx, "explanation"] = str(df.at[idx, "explanation"]) + suffix

    return df
