# Changelog

All notable changes to this project are documented here.

Release dates reflect when a version was **tagged on GitHub** (Release), not when the repo first went public or when each feature was first written.

## [Unreleased]

## [1.1.0] - 2026-06-19

### Added

- SHAP feature attribution (`explainability.py`) on confidence-gated alerts; hybrid rule-based + top-feature explanations
- Docker support (`Dockerfile`, `docker-compose.yml`) for local and portable deployment
- CI `docker-build` job in GitHub Actions
- `docs/architecture.md` — full system design reference
- Project branding assets (`assets/icon.svg`, `logo.svg`, `logo-dark.svg`, `favicon.png`)
- Committed runtime artifacts: `output/isolation_forest_model.pkl` (for local SHAP re-runs)
- Tests for SHAP and gated-alert UI behavior (92 offline tests total)

### Changed

- README restructured (TOC, CI/CD table, alerts vs risk bands, theme-aware logos)
- Streamlit main table shows confidence-gated alerts (`flagged == true`), not all non-Normal risk bands
- Sample `output/scored_events_gated.parquet` refreshed with SHAP-augmented explanations (19 gated alerts / 366 events)
- `.gitignore` — commit only sample parquet, threshold config, and saved model under `output/`

### Fixed

- Sidebar “How it works” inline-code contrast (white-on-white `flagged` / `risk_level` snippets)
- Sidebar metrics aligned with confidence-gated alert count

## [1.0.0] - 2026-06-18

First **tagged** release (June 2026). The repo and Streamlit app were already **public since March 2026**; CI, tests, and README polish were added in June before this tag.

### Added (June 2026 — pre-release)

- Offline test suite and GitHub Actions CI (Python 3.11 / 3.12; 81 tests)
- README table of contents and reorganization

### Included (March 2026 — initial implementation)

- Multi-source EDR log ingest (CrowdStrike Falcon NDJSON, Sysmon XML, Windows Security 4688)
- Feature engineering pipeline — 12 interpretable behavioral features
- Isolation Forest training and anomaly scoring
- Confidence gating with rule-based SOC explanations and threshold config JSON
- Streamlit triage dashboard (sample data, upload validation, filters, CSV export)
- Streamlit Cloud deployment
- README with architecture overview, quick start, data attribution, and safety considerations

[Unreleased]: https://github.com/rvong65/breach-precursor-detector/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/rvong65/breach-precursor-detector/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rvong65/breach-precursor-detector/releases/tag/v1.0.0
