"""End-to-end tests for DH socket engine, feature extraction, AI detector, and Flask API."""

from __future__ import annotations

import random
import unittest

from app import app
from detector import DHMitmDetector
from dh_engine import run_socket_dh_session
from features import FEATURE_NAMES, extract_feature_vector


class TestDHMitmPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = DHMitmDetector()
        cls.metrics = cls.detector.fit_and_evaluate(n_normal=300, n_attack=120, seed=7)

    def test_honest_socket_dh_exchange_matches_secret(self) -> None:
        session = run_socket_dh_session("none", rng=random.Random(10))
        self.assertTrue(session.secrets_match)
        self.assertFalse(session.attacker_intercepted)
        self.assertEqual(session.alice_secret_fp, session.bob_secret_fp)

    def test_mitm_socket_dh_exchange_splits_secret(self) -> None:
        for profile in ("active_mitm", "stealth_mitm", "retry_mitm"):
            session = run_socket_dh_session(profile, rng=random.Random(11))  # type: ignore[arg-type]
            self.assertFalse(session.secrets_match)
            self.assertTrue(session.attacker_intercepted)
            self.assertNotEqual(session.alice_secret_fp, session.bob_secret_fp)

    def test_feature_vector_excludes_secrets_and_matches_schema(self) -> None:
        session = run_socket_dh_session("none", rng=random.Random(12))
        vec = extract_feature_vector(session.telemetry)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertNotIn("alice_secret_fp", FEATURE_NAMES)
        self.assertNotIn("bob_secret_fp", FEATURE_NAMES)

    def test_detector_scores_normal_low_and_mitm_high_with_indicators(self) -> None:
        normal_session = run_socket_dh_session("none", rng=random.Random(21))
        normal_verdict = self.detector.score_session(normal_session.telemetry)
        self.assertFalse(normal_verdict.is_anomalous)
        self.assertLess(normal_verdict.risk_score, 45)

        mitm_session = run_socket_dh_session("active_mitm", rng=random.Random(22))
        mitm_verdict = self.detector.score_session(mitm_session.telemetry)
        self.assertTrue(mitm_verdict.is_anomalous)
        self.assertGreaterEqual(mitm_verdict.risk_score, 70)
        self.assertTrue(len(mitm_verdict.indicators) > 0)

    def test_comparison_baselines_populated(self) -> None:
        model_names = {m["model"] for m in self.metrics}
        self.assertIn("Isolation Forest (Primary)", model_names)
        self.assertIn("Random Forest", model_names)
        self.assertIn("Gradient Boosting", model_names)
        self.assertIn("ANN (MLP)", model_names)
        for m in self.metrics:
            self.assertGreater(m["roc_auc"], 0.85)

    def test_flask_endpoints(self) -> None:
        client = app.test_client()
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/api/metrics").status_code, 200)

        res_norm = client.post("/api/simulate", json={"attack_profile": "none"})
        self.assertEqual(res_norm.status_code, 200)
        data_norm = res_norm.get_json()
        self.assertTrue(data_norm["session"]["secrets_match"])

        res_mitm = client.post("/api/simulate", json={"attack_profile": "active_mitm", "ai_enabled": True})
        self.assertEqual(res_mitm.status_code, 200)
        data_mitm = res_mitm.get_json()
        self.assertFalse(data_mitm["session"]["secrets_match"])
        self.assertTrue(data_mitm["detection"]["is_anomalous"])

        res_ai_off = client.post("/api/simulate", json={"attack_profile": "active_mitm", "ai_enabled": False})
        self.assertEqual(res_ai_off.status_code, 200)
        data_off = res_ai_off.get_json()
        self.assertFalse(data_off["ai_enabled"])
        self.assertIsNone(data_off["detection"]["risk_score"])
        self.assertFalse(data_off["detection"]["is_anomalous"])
        self.assertEqual(data_off["detection"]["verdict"], "AI DISABLED — UNMONITORED")

        res_sessions = client.get("/api/sessions")
        self.assertEqual(res_sessions.status_code, 200)
        self.assertGreaterEqual(len(res_sessions.get_json()["sessions"]), 2)


if __name__ == "__main__":
    unittest.main()
