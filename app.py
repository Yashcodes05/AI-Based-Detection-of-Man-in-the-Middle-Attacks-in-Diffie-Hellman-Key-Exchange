"""Flask Web Dashboard & API for AI-Based DH MITM Detection."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, render_template, request

from detector import DHMitmDetector
from dh_engine import AttackProfile, run_socket_dh_session

app = Flask(__name__)
detector = DHMitmDetector.load_or_train()
session_history: deque[dict[str, Any]] = deque(maxlen=60)

VALID_PROFILES: set[str] = {"none", "active_mitm", "stealth_mitm", "retry_mitm"}


@app.route("/")
def index() -> str:
    return render_template("index.html")


def _run_and_record(attack_profile: AttackProfile, ai_enabled: bool) -> dict[str, Any]:
    session = run_socket_dh_session(attack_profile=attack_profile)
    if ai_enabled:
        verdict = detector.score_session(session.telemetry).to_dict()
    else:
        verdict = {
            "risk_score": 0,
            "risk_level": "NORMAL",
            "verdict": "ACCEPTED (NO AI)",
            "is_anomalous": False,
            "raw_anomaly_score": 0.0,
            "indicators": [],
        }

    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "ai_enabled": ai_enabled,
        "session": session.to_dict(),
        "detection": verdict,
        "feature_details": detector.get_feature_breakdown(session.telemetry),
    }
    session_history.appendleft(record)
    return record


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    payload = request.get_json(silent=True) or {}
    profile = str(payload.get("attack_profile", "none"))
    if profile not in VALID_PROFILES:
        return jsonify({"error": f"Invalid attack_profile: {profile}"}), 400

    ai_enabled = bool(payload.get("ai_enabled", True))
    attack_profile: AttackProfile = profile  # type: ignore[assignment]
    return jsonify(_run_and_record(attack_profile, ai_enabled))


@app.route("/api/simulate_batch", methods=["POST"])
def api_simulate_batch():
    payload = request.get_json(silent=True) or {}
    ai_enabled = bool(payload.get("ai_enabled", True))
    profiles: list[AttackProfile] = [
        "none",
        "none",
        "active_mitm",
        "none",
        "stealth_mitm",
        "none",
        "retry_mitm",
        "none",
        "active_mitm",
        "none",
    ]
    results = [_run_and_record(p, ai_enabled) for p in profiles]
    return jsonify({"count": len(results), "latest": results[-1]})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    session_history.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    return jsonify({"metrics": detector.comparison_metrics})


@app.route("/api/retrain", methods=["POST"])
def api_retrain():
    metrics = detector.fit_and_evaluate()
    detector.save()
    return jsonify({"status": "retrained", "metrics": metrics})


@app.route("/api/sessions", methods=["GET"])
def api_sessions():
    return jsonify({"sessions": list(session_history)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
