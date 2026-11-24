"""Diffie-Hellman Key Exchange and MITM Attack Simulator over local TCP sockets.

Implements:
1. Honest Alice <-> Bob Diffie-Hellman key exchange over real local TCP sockets.
2. Active MITM Attacker proxy (Alice <-> Attacker <-> Bob) substituting public
   DH values so Alice shares K1 with Attacker and Bob shares K2 with Attacker.
3. Synthetic baseline & attack telemetry generator for training and benchmarking
   the AI anomaly detection pipeline without exposing cryptographic secrets.
"""

from __future__ import annotations

import hashlib
import json
import random
import secrets
import socket
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Literal

# RFC 3526 2048-bit MODP Group (Group 14) prime
RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_G = 2

AttackProfile = Literal["none", "active_mitm", "stealth_mitm", "retry_mitm"]


def short_fingerprint(value: int) -> str:
    """Return a readable SHA-256 prefix for displaying large DH integers."""
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return f"{digest[:12]}...{digest[-6:]}"


@dataclass
class DHSessionResult:
    """Complete record of a DH handshake: crypto view + observable telemetry."""

    session_id: str
    mode: str
    attack_profile: str
    is_attack: int
    alice_pub_fp: str
    bob_pub_fp: str
    alice_secret_fp: str
    bob_secret_fp: str
    secrets_match: bool
    attacker_intercepted: bool
    telemetry: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _recv_json(conn: socket.socket) -> dict[str, Any]:
    buf = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
    line = bytes(buf).split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8"))


def _send_json(conn: socket.socket, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload) + "\n").encode("utf-8")
    conn.sendall(data)


def run_socket_dh_session(
    attack_profile: AttackProfile = "none",
    rng: random.Random | None = None,
) -> DHSessionResult:
    """Execute a real local TCP socket Diffie-Hellman handshake.

    In 'none' mode, Alice connects directly to Bob.
    In MITM modes, Alice connects to Attacker, who proxies and substitutes
    DH public keys with Bob, creating K1 (Alice<->Attacker) and K2 (Attacker<->Bob).
    """
    r = rng or random.Random()
    session_id = f"sess-{secrets.token_hex(4)}"
    is_attack = attack_profile != "none"

    bob_priv = secrets.randbelow(RFC3526_P - 3) + 2
    bob_pub = pow(RFC3526_G, bob_priv, RFC3526_P)
    bob_shared: dict[str, int] = {}
    bob_ready = threading.Event()

    def bob_server(port_holder: list[int]) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            port_holder.append(srv.getsockname()[1])
            bob_ready.set()

            retries_handled = 0
            expected_conns = 2 if attack_profile == "retry_mitm" else 1
            while retries_handled < expected_conns:
                conn, _ = srv.accept()
                with conn:
                    msg = _recv_json(conn)
                    alice_or_eve_pub = int(msg["pub_key"])
                    _send_json(conn, {"pub_key": str(bob_pub)})
                    bob_shared["k"] = pow(alice_or_eve_pub, bob_priv, RFC3526_P)
                    retries_handled += 1

    bob_port_holder: list[int] = []
    bob_thread = threading.Thread(target=bob_server, args=(bob_port_holder,), daemon=True)
    bob_thread.start()
    bob_ready.wait(timeout=3.0)
    bob_port = bob_port_holder[0]

    attacker_port_holder: list[int] = []
    attacker_ready = threading.Event()
    attacker_secrets: dict[str, int] = {}

    if is_attack:
        eve_priv_alice = secrets.randbelow(RFC3526_P - 3) + 2
        eve_pub_for_alice = pow(RFC3526_G, eve_priv_alice, RFC3526_P)
        eve_priv_bob = secrets.randbelow(RFC3526_P - 3) + 2
        eve_pub_for_bob = pow(RFC3526_G, eve_priv_bob, RFC3526_P)

        def mitm_proxy() -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
                proxy.bind(("127.0.0.1", 0))
                proxy.listen(4)
                attacker_port_holder.append(proxy.getsockname()[1])
                attacker_ready.set()

                conns_to_handle = 2 if attack_profile == "retry_mitm" else 1
                for _ in range(conns_to_handle):
                    alice_conn, _ = proxy.accept()
                    with alice_conn:
                        msg_from_alice = _recv_json(alice_conn)
                        alice_pub_val = int(msg_from_alice["pub_key"])

                        # Simulated interception/forwarding overhead
                        if attack_profile == "stealth_mitm":
                            time.sleep(r.uniform(0.008, 0.018))
                        elif attack_profile == "retry_mitm":
                            time.sleep(r.uniform(0.035, 0.075))
                        else:
                            time.sleep(r.uniform(0.020, 0.045))

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as to_bob:
                            to_bob.connect(("127.0.0.1", bob_port))
                            _send_json(to_bob, {"pub_key": str(eve_pub_for_bob)})
                            msg_from_bob = _recv_json(to_bob)
                            bob_pub_val = int(msg_from_bob["pub_key"])

                        attacker_secrets["k1"] = pow(alice_pub_val, eve_priv_alice, RFC3526_P)
                        attacker_secrets["k2"] = pow(bob_pub_val, eve_priv_bob, RFC3526_P)
                        _send_json(alice_conn, {"pub_key": str(eve_pub_for_alice)})

        mitm_thread = threading.Thread(target=mitm_proxy, daemon=True)
        mitm_thread.start()
        attacker_ready.wait(timeout=3.0)
        target_port = attacker_port_holder[0]
    else:
        target_port = bob_port

    alice_priv = secrets.randbelow(RFC3526_P - 3) + 2
    alice_pub = pow(RFC3526_G, alice_priv, RFC3526_P)

    attempts = 2 if attack_profile == "retry_mitm" else 1
    latencies_ms: list[float] = []
    t_session_start = time.perf_counter()
    received_peer_pub = 0

    for _ in range(attempts):
        t0 = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
            cli.connect(("127.0.0.1", target_port))
            _send_json(cli, {"pub_key": str(alice_pub)})
            reply = _recv_json(cli)
            received_peer_pub = int(reply["pub_key"])
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    session_duration_ms = (time.perf_counter() - t_session_start) * 1000.0
    alice_secret = pow(received_peer_pub, alice_priv, RFC3526_P)
    bob_thread.join(timeout=3.0)
    bob_secret = bob_shared["k"]

    telemetry = _build_observable_telemetry(
        attack_profile=attack_profile,
        measured_latency_ms=sum(latencies_ms) / len(latencies_ms),
        measured_duration_ms=session_duration_ms,
        rng=r,
    )

    return DHSessionResult(
        session_id=session_id,
        mode="MITM Attack" if is_attack else "Honest Exchange",
        attack_profile=attack_profile,
        is_attack=1 if is_attack else 0,
        alice_pub_fp=short_fingerprint(alice_pub),
        bob_pub_fp=short_fingerprint(bob_pub),
        alice_secret_fp=short_fingerprint(alice_secret),
        bob_secret_fp=short_fingerprint(bob_secret),
        secrets_match=(alice_secret == bob_secret),
        attacker_intercepted=is_attack,
        telemetry=telemetry,
    )


def _build_observable_telemetry(
    attack_profile: AttackProfile,
    measured_latency_ms: float | None = None,
    measured_duration_ms: float | None = None,
    rng: random.Random | None = None,
) -> dict[str, float]:
    """Build observable network, handshake, and session-behavioral telemetry.

    Note: Cryptographic secrets (a, b, K) are never included in telemetry.
    """
    r = rng or random.Random()

    if attack_profile == "none":
        base_lat = measured_latency_ms if measured_latency_ms is not None else r.gauss(8.5, 2.0)
        base_dur = measured_duration_ms if measured_duration_ms is not None else r.gauss(22.0, 4.5)
        return {
            "src_dst_changes": float(r.choices([0, 1], weights=[0.95, 0.05])[0]),
            "conn_frequency": float(max(0.5, r.gauss(2.2, 0.6))),
            "tcp_retransmissions": float(r.choices([0, 1], weights=[0.92, 0.08])[0]),
            "rst_count": float(r.choices([0, 1], weights=[0.97, 0.03])[0]),
            "path_hop_anomaly": float(max(0.0, r.gauss(0.05, 0.04))),
            "handshake_latency_ms": float(max(2.0, base_lat)),
            "latency_spread_ms": float(max(0.2, r.gauss(1.3, 0.45))),
            "handshake_retries": float(r.choices([0, 1], weights=[0.94, 0.06])[0]),
            "sequence_anomaly_score": float(max(0.0, min(1.0, r.gauss(0.06, 0.04)))),
            "auth_cert_anomaly": float(r.choices([0, 1], weights=[0.98, 0.02])[0]),
            "unseen_pattern_score": float(max(0.0, min(1.0, r.gauss(0.08, 0.05)))),
            "intermediary_host_count": 0.0,
            "session_duration_ms": float(max(5.0, base_dur)),
            "baseline_deviation": float(max(0.0, r.gauss(0.12, 0.06))),
        }

    if attack_profile == "stealth_mitm":
        lat = measured_latency_ms if measured_latency_ms is not None else r.gauss(21.0, 4.0)
        dur = measured_duration_ms if measured_duration_ms is not None else r.gauss(46.0, 8.0)
        return {
            "src_dst_changes": float(r.choices([1, 2], weights=[0.6, 0.4])[0]),
            "conn_frequency": float(max(1.0, r.gauss(4.2, 1.0))),
            "tcp_retransmissions": float(r.choices([1, 2], weights=[0.65, 0.35])[0]),
            "rst_count": float(r.choices([0, 1], weights=[0.7, 0.3])[0]),
            "path_hop_anomaly": float(max(0.2, min(1.0, r.gauss(0.58, 0.14)))),
            "handshake_latency_ms": float(max(12.0, lat)),
            "latency_spread_ms": float(max(1.5, r.gauss(5.8, 1.4))),
            "handshake_retries": float(r.choices([1, 2], weights=[0.7, 0.3])[0]),
            "sequence_anomaly_score": float(max(0.2, min(1.0, r.gauss(0.52, 0.12)))),
            "auth_cert_anomaly": float(r.choices([0, 1], weights=[0.3, 0.7])[0]),
            "unseen_pattern_score": float(max(0.2, min(1.0, r.gauss(0.64, 0.12)))),
            "intermediary_host_count": 1.0,
            "session_duration_ms": float(max(18.0, dur)),
            "baseline_deviation": float(max(0.25, r.gauss(0.68, 0.14))),
        }

    if attack_profile == "retry_mitm":
        lat = measured_latency_ms if measured_latency_ms is not None else r.gauss(48.0, 9.0)
        dur = measured_duration_ms if measured_duration_ms is not None else r.gauss(115.0, 20.0)
        return {
            "src_dst_changes": float(r.randint(2, 4)),
            "conn_frequency": float(max(2.0, r.gauss(8.5, 1.8))),
            "tcp_retransmissions": float(r.randint(3, 7)),
            "rst_count": float(r.randint(1, 4)),
            "path_hop_anomaly": float(max(0.4, min(1.0, r.gauss(0.84, 0.10)))),
            "handshake_latency_ms": float(max(25.0, lat)),
            "latency_spread_ms": float(max(4.0, r.gauss(14.5, 3.2))),
            "handshake_retries": float(r.randint(2, 5)),
            "sequence_anomaly_score": float(max(0.4, min(1.0, r.gauss(0.82, 0.10)))),
            "auth_cert_anomaly": 1.0,
            "unseen_pattern_score": float(max(0.4, min(1.0, r.gauss(0.86, 0.08)))),
            "intermediary_host_count": float(r.choices([1, 2], weights=[0.7, 0.3])[0]),
            "session_duration_ms": float(max(45.0, dur)),
            "baseline_deviation": float(max(0.4, r.gauss(0.92, 0.12))),
        }

    # active_mitm
    lat = measured_latency_ms if measured_latency_ms is not None else r.gauss(34.0, 6.5)
    dur = measured_duration_ms if measured_duration_ms is not None else r.gauss(72.0, 14.0)
    return {
        "src_dst_changes": float(r.randint(1, 3)),
        "conn_frequency": float(max(1.5, r.gauss(6.0, 1.2))),
        "tcp_retransmissions": float(r.randint(2, 4)),
        "rst_count": float(r.choices([1, 2], weights=[0.65, 0.35])[0]),
        "path_hop_anomaly": float(max(0.3, min(1.0, r.gauss(0.75, 0.11)))),
        "handshake_latency_ms": float(max(18.0, lat)),
        "latency_spread_ms": float(max(2.5, r.gauss(9.4, 2.2))),
        "handshake_retries": float(r.randint(1, 3)),
        "sequence_anomaly_score": float(max(0.3, min(1.0, r.gauss(0.71, 0.11)))),
        "auth_cert_anomaly": float(r.choices([0, 1], weights=[0.15, 0.85])[0]),
        "unseen_pattern_score": float(max(0.3, min(1.0, r.gauss(0.78, 0.10)))),
        "intermediary_host_count": 1.0,
        "session_duration_ms": float(max(30.0, dur)),
        "baseline_deviation": float(max(0.35, r.gauss(0.81, 0.12))),
    }


def generate_dataset(
    n_normal: int = 400,
    n_attack: int = 150,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """Generate labeled baseline and MITM session records for training/evaluation."""
    r = random.Random(seed)
    records: list[dict[str, Any]] = []

    for i in range(n_normal):
        tel = _build_observable_telemetry("none", rng=r)
        tel["label"] = 0
        tel["attack_profile"] = "none"
        tel["session_id"] = f"train-norm-{i:04d}"
        records.append(tel)

    profiles: list[AttackProfile] = ["active_mitm", "stealth_mitm", "retry_mitm"]
    for i in range(n_attack):
        prof = profiles[i % len(profiles)]
        tel = _build_observable_telemetry(prof, rng=r)
        tel["label"] = 1
        tel["attack_profile"] = prof
        tel["session_id"] = f"train-mitm-{i:04d}"
        records.append(tel)

    r.shuffle(records)
    return records
