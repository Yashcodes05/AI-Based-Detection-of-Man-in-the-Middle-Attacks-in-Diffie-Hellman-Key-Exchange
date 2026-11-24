"""Feature engineering for observable Diffie-Hellman handshake telemetry.

Implements the three feature categories from the proposal (Slide 7):
  A. Network-Level Features
  B. Handshake-Level Features
  C. Session-Behavioral Features
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    category: str
    indicator_label: str


FEATURE_SPECS: tuple[FeatureSpec, ...] = (
    # A. Network-Level
    FeatureSpec("src_dst_changes", "Network", "Mid-flow source/destination change"),
    FeatureSpec("conn_frequency", "Network", "Abnormal connection frequency"),
    FeatureSpec("tcp_retransmissions", "Network", "Elevated TCP retransmissions"),
    FeatureSpec("rst_count", "Network", "Unexpected TCP RST packets"),
    FeatureSpec("path_hop_anomaly", "Network", "Network-path anomaly"),
    # B. Handshake-Level
    FeatureSpec("handshake_latency_ms", "Handshake", "Unusual handshake timing"),
    FeatureSpec("latency_spread_ms", "Handshake", "High handshake latency spread"),
    FeatureSpec("handshake_retries", "Handshake", "Repeated handshake attempts"),
    FeatureSpec("sequence_anomaly_score", "Handshake", "Unexpected handshake sequence"),
    FeatureSpec("auth_cert_anomaly", "Handshake", "Certificate / authentication anomaly"),
    # C. Session-Behavioral
    FeatureSpec("unseen_pattern_score", "Behavioral", "Unseen communication pattern"),
    FeatureSpec("intermediary_host_count", "Behavioral", "Unexpected intermediary host"),
    FeatureSpec("session_duration_ms", "Behavioral", "Abnormal session duration"),
    FeatureSpec("baseline_deviation", "Behavioral", "Deviation from learned baseline"),
)

FEATURE_NAMES: list[str] = [spec.name for spec in FEATURE_SPECS]
FEATURE_SPEC_MAP: dict[str, FeatureSpec] = {spec.name: spec for spec in FEATURE_SPECS}


def extract_feature_vector(telemetry: dict[str, Any]) -> np.ndarray:
    """Convert a single session telemetry dict into a 1D float64 feature vector."""
    return np.array([float(telemetry.get(name, 0.0)) for name in FEATURE_NAMES], dtype=np.float64)


def records_to_dataframe(records: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert a list of telemetry records into a DataFrame ordered by FEATURE_NAMES."""
    rows = [{name: float(rec.get(name, 0.0)) for name in FEATURE_NAMES} for rec in records]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)
