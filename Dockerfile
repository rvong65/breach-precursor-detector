FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app.py confidence_gating.py explainability.py feature_engineering.py \
     load_events.py train_isolation_forest.py ./
COPY loaders/ ./loaders/
COPY assets/ ./assets/
COPY output/scored_events_gated.parquet output/threshold_config.json ./output/

EXPOSE 8501

CMD ["streamlit", "run", "app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
