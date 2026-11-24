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
session_history: deque[dict[str, Any]] = deque(maxlen=25)

VALID_PROFILES: set[str] = {"none", "active_mitm", "stealth_mitm", "retry_mitm"}


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    payload = request.get_json(silent=True) or {}
    profile = str(payload.get("attack_profile", "none"))
    if profile not in VALID_PROFILES:
        return jsonify({"error": f"Invalid attack_profile: {profile}"}), 400

    attack_profile: AttackProfile = profile  # type: ignore[assignment]
    session = run_socket_dh_session(attack_profile=attack_profile)
    verdict = detector.score_session(session.telemetry)

    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "session": session.to_dict(),
        "detection": verdict.to_dict(),
    }
    session_history.appendleft(record)
    return jsonify(record)


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
