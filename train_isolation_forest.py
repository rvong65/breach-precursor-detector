"""
Train Isolation Forest on features, score events, evaluate vs heuristic labels.

Loads X_features.parquet (and optional y_labels.parquet, events_prepped.parquet),
trains sklearn IsolationForest (unsupervised), scores data, merges trace columns,
evaluates vs weak labels, saves model and scored_events.parquet.
"""

import argparse
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score


# -----------------------------------------------------------------------------
# Load and prepare X
# -----------------------------------------------------------------------------


def load_data(
    x_path: Path,
    events_path: Path | None = None,
    y_path: Path | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series | None]:
    """
    Load X_features, events_prepped (for trace cols), and optional y_labels.
    Returns (X_full, events_prep, y_optional).
    """
    X = pd.read_parquet(x_path)
    events_prep = pd.read_parquet(events_path) if events_path and events_path.exists() else pd.DataFrame()
    y = None
    if y_path and y_path.exists():
        y_df = pd.read_parquet(y_path)
        if "is_attack" in y_df.columns:
            y = y_df["is_attack"]
        elif len(y_df.columns) == 1:
            y = y_df.iloc[:, 0]
        else:
            y = None
    return X, events_prep, y


def prepare_X_train(X: pd.DataFrame) -> pd.DataFrame:
    """
    Build numeric-only training matrix. Drop non-numeric (e.g. timestamp), fill NaN with 0.
    Isolation Forest is scale-invariant; no scaling applied.
    """
    numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    X_train = X[numeric_cols].copy()
    X_train = X_train.fillna(0)
    return X_train


# -----------------------------------------------------------------------------
# Train and score
# -----------------------------------------------------------------------------


def train_model(
    X: pd.DataFrame,
    *,
    contamination: float | str = 0.05,
    n_estimators: int = 150,
    max_samples: int | str = 256,
    random_state: int = 42,
) -> IsolationForest:
    """Fit IsolationForest on X (unsupervised)."""
    model = IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        max_samples=max_samples,
        random_state=random_state,
    )
    model.fit(X)
    return model


def score_data(
    model: IsolationForest,
    X: pd.DataFrame,
    events_prep: pd.DataFrame,
    X_train: pd.DataFrame,
) -> pd.DataFrame:
    """
    Score X with model, attach anomaly_score and is_anomaly, merge trace columns.
    Returns scored DataFrame with index aligned to X.
    """
    scores = model.decision_function(X_train)
    preds = model.predict(X_train)
    # -1 = anomaly, 1 = normal; store is_anomaly as 1/0
    is_anomaly = (preds == -1).astype(int)

    df_scored = pd.DataFrame(
        {"anomaly_score": scores, "is_anomaly": is_anomaly},
        index=X.index,
    )

    trace_cols = ["timestamp", "source", "command_line", "process_image", "parent_image", "event_type"]
    if not events_prep.empty and X.index.isin(events_prep.index).any():
        available = [c for c in trace_cols if c in events_prep.columns]
        if available:
            df_scored = df_scored.join(events_prep[available], how="left")
    else:
        if "timestamp" in X.columns:
            df_scored["timestamp"] = X["timestamp"].values
        for c in ["source", "command_line", "process_image", "parent_image", "event_type"]:
            if c not in df_scored.columns:
                df_scored[c] = None

    return df_scored


# -----------------------------------------------------------------------------
# Evaluate and save
# -----------------------------------------------------------------------------


def evaluate(
    model: IsolationForest,
    df_scored: pd.DataFrame,
    y_true: pd.Series | None,
    output_dir: Path,
    *,
    top_n: int = 20,
) -> None:
    """
    If y_true: precision/recall/F1 of predicted anomaly vs is_attack.
    Histogram of anomaly_score; top N anomalies; threshold ideas.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if y_true is not None and df_scored.index.isin(y_true.index).any():
        y_aligned = y_true.reindex(df_scored.index).fillna(0).astype(int)
        pred_binary = df_scored["is_anomaly"].values
        # Treat is_attack as positive; pred_binary 1 = anomaly
        p = precision_score(y_aligned, pred_binary, zero_division=0)
        r = recall_score(y_aligned, pred_binary, zero_division=0)
        f1 = f1_score(y_aligned, pred_binary, zero_division=0)
        print("\n--- Evaluation vs heuristic labels (is_attack) ---")
        print(f"  Precision: {p:.4f}  Recall: {r:.4f}  F1: {f1:.4f}")

    # Score distribution histogram
    fig, ax = plt.subplots()
    ax.hist(df_scored["anomaly_score"].dropna(), bins=min(50, len(df_scored)), edgecolor="black", alpha=0.7)
    ax.set_xlabel("anomaly_score (lower = more anomalous)")
    ax.set_ylabel("count")
    ax.set_title("Anomaly score distribution")
    fig.savefig(output_dir / "anomaly_score_hist.png", bbox_inches="tight")
    plt.close(fig)
    print(f"\nSaved score histogram to {output_dir / 'anomaly_score_hist.png'}")

    # Threshold ideas
    s = df_scored["anomaly_score"]
    p5 = s.quantile(0.05)
    p10 = s.quantile(0.10)
    print("\n--- Threshold ideas ---")
    print(f"  Bottom 5%:  score < {p5:.4f}")
    print(f"  Bottom 10%: score < {p10:.4f}")
    print("  Or use a fixed threshold, e.g. score < -0.05")

    # Top N anomalies (lowest score)
    show_cols = [c for c in ["timestamp", "process_image", "parent_image", "command_line", "anomaly_score"] if c in df_scored.columns]
    top = df_scored.sort_values("anomaly_score").head(top_n)[show_cols]
    top_path = output_dir / "top_anomalies.csv"
    top.to_csv(top_path, index=True)
    print(f"\n--- Top {top_n} anomalies (lowest score) ---")
    print(top.to_string())
    print(f"\nSaved to {top_path}")


def save_model(model: IsolationForest, path: Path) -> None:
    """Serialize model with joblib."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    print(f"Saved model to {path}")


def save_scored_df(df: pd.DataFrame, path: Path) -> None:
    """Write scored events to parquet."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=True)
    print(f"Saved scored events to {path}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Isolation Forest and score events.")
    parser.add_argument("--x-path", type=Path, default=Path("output/X_features.parquet"), help="Path to X_features.parquet")
    parser.add_argument("--y-path", type=Path, default=Path("output/y_labels.parquet"), help="Optional path to y_labels.parquet")
    parser.add_argument("--events-path", type=Path, default=Path("output/events_prepped.parquet"), help="Path to events_prepped.parquet")
    parser.add_argument("--output-dir", type=Path, default=Path("output"), help="Output directory")
    parser.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination (0.01-0.1)")
    parser.add_argument("--n-estimators", type=int, default=150, help="Number of trees")
    parser.add_argument("--max-samples", type=int, default=256, help="Max samples per tree (int or 'auto')")
    parser.add_argument("--top-n", type=int, default=20, help="Number of top anomalies to print/save")
    args = parser.parse_args()

    print("Loading data...")
    X, events_prep, y_true = load_data(args.x_path, args.events_path, args.y_path)
    if X.empty:
        print("X is empty. Exiting.")
        return

    X_train = prepare_X_train(X)
    print(f"X_train shape: {X_train.shape}")

    print("Training Isolation Forest...")
    model = train_model(
        X_train,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
        random_state=42,
    )

    print("Scoring data...")
    df_scored = score_data(model, X, events_prep, X_train)

    print("\n--- Model params ---")
    for k, v in model.get_params().items():
        print(f"  {k}: {v}")

    print("\n--- Score stats ---")
    print(df_scored["anomaly_score"].describe().to_string())

    evaluate(model, df_scored, y_true, args.output_dir, top_n=args.top_n)

    save_model(model, args.output_dir / "isolation_forest_model.pkl")
    save_scored_df(df_scored, args.output_dir / "scored_events.parquet")

    print("\n--- Top 10 anomalies (inspect) ---")
    show = [c for c in ["timestamp", "process_image", "parent_image", "command_line", "anomaly_score"] if c in df_scored.columns]
    print(df_scored.sort_values("anomaly_score").head(10)[show].to_string())
    print("Done.")


if __name__ == "__main__":
    main()
