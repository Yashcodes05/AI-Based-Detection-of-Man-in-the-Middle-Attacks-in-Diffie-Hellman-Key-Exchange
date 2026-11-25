# AI-Based Detection of Man-in-the-Middle Attacks in Diffie–Hellman Key Exchange

An AI-driven behavioral anomaly detection layer for identifying Man-in-the-Middle (MITM) attacks during Diffie–Hellman (DH) key exchange — **without** inspecting or attempting to recover cryptographic secrets.

## Architecture

1. **Diffie–Hellman Socket Simulator (`dh_engine.py`)** 
   - Executes real local TCP socket DH handshakes using RFC 3526 2048-bit MODP Group 14 (`p`, `g = 2`).
   - Supports **Honest Exchange** (`Alice ↔ Bob`, establishing identical `K`) and **Active MITM Proxy** (`Alice ↔ Attacker ↔ Bob`, establishing split keys `K1 ≠ K2`) across `active_mitm`, `stealth_mitm`, and `retry_mitm` profiles.
2. **Observable Feature Engineering (`features.py`)**
   - **Network-level:** mid-flow source/destination changes, connection frequency, TCP retransmissions, RST counts, network-path anomaly.
   - **Handshake-level:** handshake latency, latency spread, retries, sequence anomaly score, authentication/certificate anomaly.
   - **Session-behavioral:** unseen pattern score, intermediary host count, session duration, baseline deviation.
3. **AI / ML Detection (`detector.py`)**
   - **Primary Model:** `IsolationForest` trained **only on normal baseline traffic** (unsupervised anomaly detection).
   - **Risk Scoring & Explainability:** Maps anomaly scores to a `0–100` Risk Score (`LOW` / `MEDIUM` / `HIGH`) with per-feature z-score indicators.
   - **Comparison Baselines:** Evaluates `Isolation Forest` side-by-side against `Random Forest`, `Gradient Boosting`, and `ANN (MLP)`.
4. **Live Web Dashboard (`app.py`)**
   - Interactive Flask UI to trigger real socket handshakes, inspect DH key fingerprints, view the live 0–100 Risk Score and interpretable indicators, and compare model metrics.

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Running Tests

```bash
python -m unittest discover -s tests -v
```
