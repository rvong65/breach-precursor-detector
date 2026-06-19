"""
Breach Precursor Detector – Streamlit dashboard.

Early indicators of process injection and credential access.
Upload scored events (parquet/csv) or load sample data; view flagged events with
risk levels and explanations. Confidence gating + human-readable explanations
reduce alert fatigue and support analyst oversight.

Run: streamlit run app.py
"""

import io
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st

# Sample data path (relative to project root)
SAMPLE_PARQUET = Path("output/scored_events_gated.parquet")
THRESHOLD_CONFIG = Path("output/threshold_config.json")
ASSETS_DIR = Path("assets")
ICON_SVG = ASSETS_DIR / "icon.svg"
FAVICON_PNG = ASSETS_DIR / "favicon.png"
TRUNCATE_CMD = 80
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Normal": 4}
REQUIRED_COLS = ["timestamp", "risk_level", "process_image", "parent_image", "command_line", "explanation", "anomaly_score"]


def _inline_svg_img(path: Path, width: int, height: int, css_class: str = "") -> str:
    """Embed a local SVG as a data URI for use in st.markdown HTML."""
    if not path.exists():
        return ""
    svg = path.read_text(encoding="utf-8")
    import base64

    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    cls = f' class="{css_class}"' if css_class else ""
    return f'<img src="data:image/svg+xml;base64,{b64}" width="{width}" height="{height}" alt=""{cls}/>'


def inject_css() -> None:
    """Inject custom dark SOC-style theme tweaks. Ensures high-contrast light text on dark backgrounds."""
    st.markdown(
        """
        <style>
        :root {
            --bp-bg: #050910;
            --bp-surface: #0f172a;
            --bp-surface-soft: #1f2937;
            --bp-border-subtle: #374151;
            --bp-text: #e5e7eb;
            --bp-text-muted: #9ca3af;
            --bp-accent: #0ea5e9;
            --bp-critical: #f97373;
            --bp-high: #fb923c;
            --bp-medium: #facc15;
            --bp-low: #a3e635;
            --bp-normal: #4b5563;
        }

        /* App and main content area – base text color */
        .stApp, .stApp * {
            color: #e5e7eb;
        }
        .stApp {
            background-color: var(--bp-bg);
        }

        /* Top bar (Deploy / Streamlit header) – remove white block */
        header[data-testid="stHeader"],
        .stApp header,
        [data-testid="stHeader"] {
            background-color: #0f172a !important;
            color: #e5e7eb !important;
        }
        [data-testid="stHeader"] * {
            color: #e5e7eb !important;
        }

        /* Widget labels (Risk level, Keyword, Sort by, Ascending, etc.) – must stay light on dark; slightly larger */
        [data-testid="stWidgetLabel"],
        [data-testid="stWidgetLabel"] *,
        label,
        label p,
        .stMarkdown,
        .stMarkdown p {
            color: #e5e7eb !important;
            font-size: 1.05rem;
        }
        /* Keep title, description, expander headers light (override any broad dark rule) */
        .bp-header,
        .bp-header *,
        [data-testid="stExpander"] details summary,
        [data-testid="stExpander"] details summary * {
            color: #e5e7eb !important;
        }
        /* Input/textarea content – keep dark on Streamlit's light input background */
        input, textarea, [data-baseweb="input"] {
            color: #111827 !important;
        }

        /* Sidebar – background and all text */
        section[data-testid="stSidebar"] {
            background-color: var(--bp-surface);
            border-right: 1px solid var(--bp-border-subtle);
            color: #e5e7eb;
        }
        section[data-testid="stSidebar"] *,
        section[data-testid="stSidebar"] p,
        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] .stMarkdown {
            color: #e5e7eb !important;
        }
        /* Inline code in sidebar markdown (How it works) – dark chip, light text */
        section[data-testid="stSidebar"] code,
        section[data-testid="stSidebar"] .stMarkdown code,
        [data-testid="stExpander"] .streamlit-expanderContent code,
        [data-testid="stExpander"] .streamlit-expanderContent .stMarkdown code {
            background-color: #1f2937 !important;
            color: #7dd3fc !important;
            padding: 0.12rem 0.4rem;
            border-radius: 0.25rem;
            border: 1px solid #374151;
            font-size: 0.88em;
        }

        /* Summary metrics – card background and readable text */
        div[data-testid="stMetric"] {
            background-color: var(--bp-surface-soft);
            border-radius: 0.4rem;
            padding: 0.65rem 0.6rem;
            border: 1px solid var(--bp-border-subtle);
        }
        div[data-testid="stMetricLabel"],
        div[data-testid="stMetric"] label {
            color: #9ca3af !important;
            font-size: 0.75rem;
        }
        div[data-testid="stMetricValue"] {
            color: #f9fafb !important;
            font-size: 1.1rem;
        }

        /* Buttons – dark background, light text */
        .stButton button,
        .stDownloadButton button,
        [data-testid="stDownloadButton"] button,
        button[kind="primary"] {
            background-color: #0f172a !important;
            color: #f9fafb !important;
            border: 1px solid #0ea5e9;
            border-radius: 0.35rem;
            padding: 0.3rem 0.9rem;
            font-weight: 500;
        }
        .stButton button:hover,
        .stDownloadButton button:hover {
            border-color: #38bdf8;
            box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.5);
        }

        /* Dataframe – light text; no Styler to avoid scroll glitches */
        .stDataFrame,
        .stDataFrame table,
        .stDataFrame td,
        .stDataFrame th {
            color: #e5e7eb !important;
            background-color: #111827;
        }
        .stDataFrame thead th {
            background-color: #1f2937 !important;
            color: #e5e7eb !important;
        }

        /* Custom header block */
        .bp-header {
            padding: 0.5rem 0 1.25rem 0;
            border-bottom: 1px solid var(--bp-border-subtle);
            margin-bottom: 0.5rem;
        }
        .bp-header-title { display: flex; align-items: center; gap: 0.75rem; }
        .bp-header-icon { width: 2.25rem; height: 2.25rem; flex-shrink: 0; }
        .bp-header-text h1 { font-size: 1.4rem; margin: 0; color: #e5e7eb; }
        .bp-header-text p { margin: 0.15rem 0 0 0; font-size: 0.95rem; color: #9ca3af; }

        /* Risk legend badges */
        .bp-risk-legend { font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.3rem; }
        .bp-badge {
            display: inline-block;
            padding: 0.1rem 0.45rem;
            border-radius: 999px;
            margin-right: 0.25rem;
            font-size: 0.7rem;
            font-weight: 500;
        }
        .bp-badge-critical { background-color: var(--bp-critical); color: #111827; }
        .bp-badge-high { background-color: var(--bp-high); color: #111827; }
        .bp-badge-medium { background-color: var(--bp-medium); color: #111827; }
        .bp-badge-low { background-color: var(--bp-low); color: #111827; }
        .bp-badge-normal { background-color: var(--bp-normal); color: #e5e7eb; }

        /* Elements with white/light background – dark text and icons for readability (#111827) */
        [data-testid="stFileUploader"],
        [data-testid="stFileUploader"] *,
        section[data-testid="stFileUploader"],
        [data-testid="stFileUploader"] p,
        [data-testid="stFileUploader"] span,
        [data-testid="stFileUploader"] label {
            color: #111827 !important;
        }
        [data-testid="stFileUploader"] button,
        [data-testid="stFileUploader"] a {
            color: #111827 !important;
        }
        [data-testid="stFileUploader"] ::placeholder {
            color: #111827 !important;
        }
        /* Expander header: dark background, white text, light gray border */
        [data-testid="stExpander"] details summary,
        [data-testid="stExpander"] .streamlit-expanderHeader,
        details.streamlit-expander summary {
            color: #e5e7eb !important;
            border: 1px solid #9ca3af !important;
            background-color: #0f172a !important;
            border-radius: 0.25rem;
        }
        [data-testid="stExpander"] summary *,
        [data-testid="stExpander"] details summary span,
        [data-testid="stExpander"] details summary p {
            color: #e5e7eb !important;
        }
        [data-testid="stExpander"] details summary svg,
        [data-testid="stExpander"] summary [role="img"] {
            color: #e5e7eb !important;
            fill: #e5e7eb !important;
        }
        /* Chart icons in expander content – dark fill and stroke (toolbar, Fullscreen).
           Known limitation: chart toolbar/icons may be inside an iframe or shadow DOM; parent-page CSS cannot style them, so they may remain light. */
        [data-testid="stExpander"] .streamlit-expanderContent svg,
        [data-testid="stExpander"] .streamlit-expanderContent [role="img"],
        [data-testid="stExpander"] .streamlit-expanderContent [class*="vega"] svg,
        [data-testid="stExpander"] .streamlit-expanderContent [class*="js-plot"] svg,
        [data-testid="stExpander"] .streamlit-expanderContent button svg,
        [data-testid="stExpander"] .streamlit-expanderContent a svg,
        [data-testid="stExpander"] .streamlit-expanderContent [class*="st"] svg {
            fill: #111827 !important;
            stroke: #111827 !important;
            color: #111827 !important;
        }
        /* Expander when open – one outer border so corners keep border color */
        [data-testid="stExpander"] details[open] {
            border: 1px solid #9ca3af;
            border-radius: 0.25rem;
        }
        [data-testid="stExpander"] details[open] summary {
            border: none;
            border-bottom: 1px solid #9ca3af;
            border-radius: 0.25rem 0.25rem 0 0;
        }
        [data-testid="stExpander"] details[open] .streamlit-expanderContent,
        [data-testid="stExpander"] details[open] > div:not(summary) {
            border: none;
            border-radius: 0 0 0.25rem 0.25rem;
        }
        /* Full command line expander – black text only (keep default white background). Disabled state and WebKit need explicit overrides. */
        [data-testid="stExpander"] .streamlit-expanderContent textarea,
        [data-testid="stExpander"] .streamlit-expanderContent input,
        [data-testid="stExpander"] textarea,
        [data-testid="stExpander"] textarea:disabled,
        [data-testid="stExpander"] .streamlit-expanderContent [data-baseweb="textarea"] {
            color: #000000 !important;
            -webkit-text-fill-color: #000000 !important;
        }
        [data-testid="stSelectbox"] div,
        [data-testid="stSelectbox"] input,
        [data-testid="stSelectbox"] label,
        [data-testid="stSelectbox"] svg,
        [data-testid="stSelectbox"] [role="button"] svg {
            color: #111827 !important;
            fill: #111827 !important;
        }
        [data-testid="stMultiSelect"] svg,
        [data-testid="stMultiSelect"] [role="button"],
        [data-testid="stMultiSelect"] [role="button"] svg {
            color: #111827 !important;
            fill: #111827 !important;
        }
        /* Risk level multiselect – blue background for visible selected tags (chips); no dark borders */
        [data-testid="stMultiSelect"] [data-baseweb="tag"],
        [data-testid="stMultiSelect"] [data-baseweb="tag"] span,
        [data-testid="stMultiSelect"] [data-baseweb="tag"] *,
        [data-baseweb="tag"] {
            background-color: #0ea5e9 !important;
            color: #f9fafb !important;
            border: none !important;
            box-shadow: none !important;
        }
        /* Keyword hint – app-provided caption below input */
        [data-testid="stTextInput"] + div:not(:has(.bp-keyword-hint)) {
            display: none !important;
        }
        [data-testid="stTextInput"] [data-testid="stCaptionContainer"] {
            display: none !important;
        }
        .bp-keyword-hint, p.bp-keyword-hint {
            color: #ffffff !important;
            font-size: 0.85rem !important;
        }
        [data-testid="stDataFrame"] [data-testid="stDataFrameResizable"],
        [data-testid="stDataFrame"] .stDataFrame div[role="toolbar"],
        [data-testid="stDataFrame"] svg,
        div[data-testid="stDataFrame"] + div svg {
            color: #111827 !important;
            fill: #111827 !important;
        }

        /* Sidebar divider – visible line between sections */
        section[data-testid="stSidebar"] hr,
        section[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] hr {
            border-color: #4b5563 !important;
            border-width: 1px !important;
        }
        /* Sidebar Charts expander – dark icons (same iframe limitation may apply; icons may remain light). */
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent svg,
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent [role="img"],
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent button svg,
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent a svg,
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent [class*="st"] svg,
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent [class*="vega"] svg,
        section[data-testid="stSidebar"] [data-testid="stExpander"] .streamlit-expanderContent [class*="js-plot"] svg,
        section[data-testid="stSidebar"] [data-testid="stArrowVegaLiteChart"] svg,
        section[data-testid="stSidebar"] [data-testid="stVegaLiteChart"] svg {
            fill: #111827 !important;
            stroke: #111827 !important;
            color: #111827 !important;
        }
        /* Sidebar Charts expander when open – higher specificity for chart container and Vega toolbar. */
        section[data-testid="stSidebar"] details[open] [data-testid="stArrowVegaLiteChart"] svg,
        section[data-testid="stSidebar"] details[open] [data-testid="stArrowVegaLiteChart"] .vega-embed svg,
        section[data-testid="stSidebar"] details[open] [data-testid="stArrowVegaLiteChart"] a svg,
        section[data-testid="stSidebar"] details[open] [data-testid="stVegaLiteChart"] svg,
        section[data-testid="stSidebar"] details[open] [data-testid="stVegaLiteChart"] .vega-embed svg,
        section[data-testid="stSidebar"] details[open] [data-testid="stVegaLiteChart"] a svg {
            fill: #111827 !important;
            stroke: #111827 !important;
            color: #111827 !important;
        }

        </style>
        """,
        unsafe_allow_html=True,
    )


# Risk palette for table cell background (hex; matches legend)
RISK_COLORS = {
    "Critical": "#f97373",
    "High": "#fb923c",
    "Medium": "#facc15",
    "Low": "#a3e635",
    "Normal": "#4b5563",
}


def style_risk_column_only(df: pd.DataFrame):
    """Apply background color only to the risk level column to avoid full-row Styler scroll glitches."""
    risk_col = "Risk Level" if "Risk Level" in df.columns else ("risk_level" if "risk_level" in df.columns else None)
    if risk_col is None:
        return df.style

    def _column_style(col_series):
        if col_series.name != risk_col:
            return ["" for _ in col_series]
        return [
            f"background-color: {RISK_COLORS.get(str(v), '#374151')}; color: #111827;"
            for v in col_series
        ]

    return df.style.apply(_column_style, axis=0)


def _normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Map image/parent_image to process_image/parent_image if needed."""
    if "image" in df.columns and "process_image" not in df.columns:
        df = df.rename(columns={"image": "process_image"})
    if "parent_image" not in df.columns and "parent image" in df.columns:
        df = df.rename(columns={"parent image": "parent_image"})
    return df


def _ensure_risk_and_flagged(df: pd.DataFrame) -> pd.DataFrame:
    """If risk_level or flagged missing, infer or fill so UI does not break."""
    if "risk_level" not in df.columns and "anomaly_score" in df.columns:
        s = df["anomaly_score"]
        df["risk_level"] = "Normal"
        df.loc[s <= s.quantile(0.02), "risk_level"] = "Critical"
        df.loc[(s > s.quantile(0.02)) & (s <= s.quantile(0.05)), "risk_level"] = "High"
        df.loc[(s > s.quantile(0.05)) & (s <= s.quantile(0.10)), "risk_level"] = "Medium"
        df.loc[(s > s.quantile(0.10)) & (s <= s.quantile(0.20)), "risk_level"] = "Low"
    if "flagged" not in df.columns and "risk_level" in df.columns:
        df["flagged"] = df["risk_level"] != "Normal"
    if "explanation" not in df.columns:
        df["explanation"] = ""
    return df


def _flagged_events(df: pd.DataFrame) -> pd.DataFrame:
    """Rows shown as alerts: confidence-gated flagged when present, else risk band fallback."""
    if "flagged" in df.columns:
        return df[df["flagged"].fillna(False).astype(bool)]
    if "risk_level" in df.columns:
        return df[df["risk_level"] != "Normal"]
    return df.iloc[0:0]


@st.cache_data(ttl=300)
def load_uploaded_file(file_name: str, file_size: int, content: bytes) -> Optional[pd.DataFrame]:
    """Load parquet or csv from bytes; return normalized DataFrame or None on structural issues."""
    name_lower = file_name.lower()
    if not (name_lower.endswith(".parquet") or name_lower.endswith(".csv")):
        # Caller is responsible for showing a friendly error.
        return None

    try:
        if name_lower.endswith(".parquet"):
            df = pd.read_parquet(io.BytesIO(content))
        else:
            df = pd.read_csv(io.BytesIO(content))
    except Exception:
        return None

    # Empty file: caller can warn and stop without crashing the app.
    if df is None or df.empty:
        return df

    df = _normalize_schema(df)

    # Lightweight structural validation for uploaded scored events.
    required_upload_cols = ["timestamp", "process_image", "parent_image", "command_line", "pid", "ppid", "event_type"]
    missing = [c for c in required_upload_cols if c not in df.columns]
    if missing:
        return None

    # Basic type sanity checks – do not raise, only inform rejection.
    try:
        ts_parsed = pd.to_datetime(df["timestamp"], errors="coerce")
        if ts_parsed.notna().sum() == 0:
            return None
    except Exception:
        return None

    try:
        pid_numeric = pd.to_numeric(df["pid"], errors="coerce")
        ppid_numeric = pd.to_numeric(df["ppid"], errors="coerce")
        if pid_numeric.notna().sum() == 0 or ppid_numeric.notna().sum() == 0:
            return None
        df["pid"] = pid_numeric
        df["ppid"] = ppid_numeric
    except Exception:
        return None

    df = _ensure_risk_and_flagged(df)
    return df


@st.cache_data(ttl=300)
def load_sample_parquet(path: Path) -> Optional[pd.DataFrame]:
    """Load sample parquet from disk."""
    if not path.exists():
        return None
    try:
        df = pd.read_parquet(path)
    except Exception:
        return None
    df = _normalize_schema(df)
    df = _ensure_risk_and_flagged(df)
    return df


def init_session_state():
    if "df" not in st.session_state:
        st.session_state.df = None
    if "data_source" not in st.session_state:
        st.session_state.data_source = None


def main():
    page_icon = str(FAVICON_PNG) if FAVICON_PNG.exists() else "🛡️"
    st.set_page_config(page_title="Breach Precursor Detector", page_icon=page_icon, layout="wide")
    init_session_state()

    inject_css()

    logo_img = _inline_svg_img(ICON_SVG, 36, 36, "bp-header-icon")
    st.markdown(
        f"""
        <div class="bp-header">
          <div class="bp-header-title">
            <div class="bp-header-icon">{logo_img or "🛡️"}</div>
            <div class="bp-header-text">
              <h1>Breach Precursor Detector</h1>
              <p>Early indicators of process injection and credential access.</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- Sidebar ---
    with st.sidebar:
        with st.expander("How it works"):
            st.markdown(
                "**Data source:** Upload a scored events file (parquet/csv) or load the built-in sample. "
                "The file should contain timestamp, process/parent image names, command line, anomaly score, "
                "and optionally risk level and explanation."
            )
            st.markdown(
                "**What you see:** The main table shows **confidence-gated alerts** only — events the pipeline marked "
                "with `flagged == true` (low anomaly score **and** a strong domain indicator such as dump precursor or "
                "suspicious parent). **Medium** and **Low** risk-band events may still appear in sidebar charts but are "
                "excluded from the alert table unless they pass gating. Filter by risk level and keyword; sort by score, time, or risk."
            )
            st.markdown(
                "**Sidebar:** Totals (events, flagged count, % flagged), top 3 riskiest process images and parent images by count of flagged events, "
                "and optional charts (risk distribution and anomaly score distribution)."
            )
            st.markdown(
                "**Export:** Download the filtered flagged events as CSV and (if available) the threshold config for reproducibility."
            )
            st.markdown(
                "Chart toolbars may show light icons (Streamlit limitation)."
            )
        st.subheader("Data")
        uploaded = st.file_uploader("Upload scored events", type=["parquet", "csv"], key="uploader")
        if uploaded is not None:
            file_name = uploaded.name or ""
            name_lower = file_name.lower()
            # Explicit extension check (defense in depth; st.file_uploader also filters).
            if not (name_lower.endswith(".csv") or name_lower.endswith(".parquet")):
                st.error("Unsupported file type. Please upload a .csv or .parquet file.")
                st.stop()

            content = uploaded.getvalue()
            try:
                df_loaded = load_uploaded_file(file_name, len(content), content)
            except Exception:
                df_loaded = None

            # Handle empty files separately: polite message + stop.
            if isinstance(df_loaded, pd.DataFrame) and df_loaded.empty:
                st.error("The file appears to be empty or invalid. Please try another file or use the sample data.")
                st.stop()

            if df_loaded is None:
                # Missing required columns or type issues.
                st.error(
                    "The uploaded file is missing required columns (timestamp, process_image or image, parent_image, command_line, pid, ppid, event_type) "
                    "or has incompatible types. Please use a file in the expected format."
                )
                st.stop()

            # Success: preserve existing behavior for valid data.
            st.session_state.df = df_loaded
            st.session_state.data_source = "upload"
            st.success(f"Loaded {len(df_loaded)} rows.")
            if len(df_loaded) == 0:
                st.warning("The file has no rows.")
            elif "timestamp" not in df_loaded.columns and "process_image" not in df_loaded.columns:
                st.warning("File is missing expected columns; display may be incomplete.")

        sample_path = SAMPLE_PARQUET
        if st.button("Load sample data", key="sample_btn"):
            df_sample = load_sample_parquet(sample_path)
            if df_sample is not None:
                st.session_state.df = df_sample
                st.session_state.data_source = "sample"
                st.success(f"Loaded {len(df_sample)} rows from {sample_path}.")
                if len(df_sample) == 0:
                    st.warning("The file has no rows.")
                elif "timestamp" not in df_sample.columns and "process_image" not in df_sample.columns:
                    st.warning("File is missing expected columns; display may be incomplete.")
            else:
                st.warning(f"Sample file not found: {sample_path}")

        st.divider()
        st.subheader("Summary")
        df = st.session_state.df
        if df is not None:
            total = len(df)
            flagged_df = _flagged_events(df)
            flagged = len(flagged_df)
            pct = 100 * flagged / total if total else 0
            m1, m2, m3 = st.columns(3)
            m1.metric("Total events", total)
            m2.metric("Flagged", flagged)
            m3.metric("% flagged", f"{pct:.1f}%")
            if not flagged_df.empty:
                top_img_s = flagged_df["process_image"].value_counts().head(3) if "process_image" in flagged_df.columns else pd.Series(dtype=int)
                top_parent_s = flagged_df["parent_image"].value_counts().head(3) if "parent_image" in flagged_df.columns else pd.Series(dtype=int)
                st.write("**Top 3 riskiest images**")
                if not top_img_s.empty:
                    top_img_df = top_img_s.reset_index()
                    top_img_df.columns = ["Image", "Count"]
                    st.dataframe(top_img_df, width="stretch", hide_index=True)
                else:
                    st.caption("No flagged images.")
                st.write("**Top 3 riskiest parents**")
                if not top_parent_s.empty:
                    top_parent_df = top_parent_s.reset_index()
                    top_parent_df.columns = ["Parent image", "Count"]
                    st.dataframe(top_parent_df, width="stretch", hide_index=True)
                else:
                    st.caption("No flagged parents.")
            with st.expander("Charts"):
                st.caption("Risk level counts")
                if "risk_level" in df.columns:
                    vc = df["risk_level"].value_counts()
                    chart_df = pd.DataFrame({"Risk Level": vc.index.tolist(), "Count": vc.values})
                    st.bar_chart(chart_df.set_index("Risk Level"))
                else:
                    st.bar_chart(pd.Series())
                if "anomaly_score" in df.columns:
                    st.caption("Anomaly score distribution (bins)")
                    binned = pd.cut(df["anomaly_score"], bins=20)
                    hist = binned.value_counts().sort_index()
                    bin_labels = [f"{iv.left:.2f} to {iv.right:.2f}" for iv in hist.index]
                    hist_df = pd.DataFrame({"Score range": bin_labels, "Count": hist.values})
                    st.bar_chart(hist_df.set_index("Score range"))
        else:
            st.info("Upload a file or load sample data.")

        st.divider()
        # Optional: export config for reproducibility (model + thresholds)
        if THRESHOLD_CONFIG.exists():
            config_bytes = THRESHOLD_CONFIG.read_bytes()
            st.download_button(
                "Download threshold config (JSON)",
                data=config_bytes,
                mime="application/json",
                file_name=THRESHOLD_CONFIG.name,
                key="download_config",
            )
        st.divider()
        st.caption("Confidence gating and human-readable explanations reduce alert fatigue and support analyst oversight.")

    # --- Main: table and filters ---
    df = st.session_state.df
    if df is None:
        st.info("Upload a parquet/csv file or click **Load sample data** in the sidebar.")
        return
    if len(df) == 0:
        st.warning("The file has no rows.")
        return
    if "timestamp" not in df.columns and "process_image" not in df.columns:
        st.warning("File is missing expected columns; display may be incomplete.")

    # Confidence-gated alerts (or risk-band fallback for uploads without flagged column)
    df_main = _flagged_events(df).copy()
    if df_main.empty:
        st.info("No flagged events (confidence-gated alerts).")
        return

    # Filters
    risk_levels = [r for r in ["Critical", "High", "Medium", "Low"] if r in df_main["risk_level"].values]
    selected_risks = st.multiselect("Risk level", options=risk_levels, default=risk_levels, key="risk_filter")
    keyword = st.text_input("Keyword in command line", key="keyword_filter", help=None)

    st.markdown('<p class="bp-keyword-hint">Press Enter to apply</p>', unsafe_allow_html=True)
    SORT_OPTIONS = ["Anomaly Score", "Risk Level", "Timestamp"]
    SORT_COL_MAP = {"Anomaly Score": "anomaly_score", "Risk Level": "risk_level", "Timestamp": "timestamp"}
    sort_label = st.selectbox("Sort by", SORT_OPTIONS, key="sort_col")
    sort_col = SORT_COL_MAP[sort_label]
    sort_asc = st.checkbox("Ascending", value=True, key="sort_asc")

    df_filtered = df_main[df_main["risk_level"].isin(selected_risks)]
    if keyword:
        cl = df_filtered["command_line"].fillna("").astype(str)
        df_filtered = df_filtered[cl.str.contains(keyword, case=False, na=False)]
    df_sorted = df_filtered.sort_values(
        by=sort_col,
        ascending=sort_asc,
        key=lambda c: c.map(RISK_ORDER) if c.name == "risk_level" else c,
    )

    st.markdown(
        """
        <div class="bp-risk-legend">
          <span class="bp-badge bp-badge-critical">Critical</span>
          <span class="bp-badge bp-badge-high">High</span>
          <span class="bp-badge bp-badge-medium">Medium</span>
          <span class="bp-badge bp-badge-low">Low</span>
          <span class="bp-badge bp-badge-normal">Normal</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Display columns – consistent Title Case headers
    display_cols = ["timestamp", "risk_level", "process_image", "parent_image", "command_line", "explanation", "anomaly_score"]
    available = [c for c in display_cols if c in df_sorted.columns]
    df_display = df_sorted[available].copy()
    if "command_line" in df_display.columns:
        df_display["command_line"] = df_display["command_line"].fillna("").astype(str).str.slice(0, TRUNCATE_CMD)
    display_rename = {
        "timestamp": "Timestamp",
        "risk_level": "Risk Level",
        "process_image": "Image",
        "parent_image": "Parent Image",
        "command_line": "Command Line (truncated)",
        "explanation": "Explanation",
        "anomaly_score": "Anomaly Score",
    }
    df_display = df_display.rename(columns={k: v for k, v in display_rename.items() if k in df_display.columns})
    styled = style_risk_column_only(df_display)
    st.dataframe(styled, width="stretch", hide_index=True)

    # Expander for full command lines (first N rows to avoid huge UI)
    with st.expander("Full command line (first 20 rows)"):
        for i, (idx, row) in enumerate(df_sorted.head(20).iterrows()):
            cmd = row.get("command_line", "")
            if pd.isna(cmd):
                cmd = ""
            st.text_area(f"Row {i+1}", value=str(cmd), height=60, key=f"cmd_{i}", disabled=True)

    st.download_button(
        "Download flagged events (CSV)",
        data=df_sorted.to_csv(index=False).encode("utf-8"),
        mime="text/csv",
        file_name="flagged_events.csv",
        key="download_btn",
    )


if __name__ == "__main__":
    main()
