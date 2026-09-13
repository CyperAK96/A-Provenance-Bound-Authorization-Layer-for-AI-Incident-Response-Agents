import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from protocol.jail_core import ProvenanceRegistry, AuthorizationLayer, Signer

INCIDENT_A = "INC-2026-0017"
INCIDENT_B = "INC-2026-0031"

def fresh_env():
    registry = ProvenanceRegistry(Signer("registry"))
    authz = AuthorizationLayer(registry, Signer("idp"))
    inv = authz.register_investigator("investigator-alice")
    event = registry.record_acquisition(INCIDENT_A, b"c2 beacon config", "host-1",
                                         "investigator-alice", "memory_dump")
    return registry, authz, inv, event

results = []

def record(name, precondition, procedure, expected, observed, success, property_violated):
    results.append(dict(attack=name, precondition=precondition, procedure=procedure,
                         expected=expected, observed=observed,
                         attack_succeeded=success, property_violated=property_violated))

# Attack: replay of an old, already-used authorization nonce
registry, authz, inv, event = fresh_env()
challenge = b"challenge-1"
sig = inv.private_key.sign(challenge).hex()
tok1, r1 = authz.authorize("investigator-alice", sig, challenge, INCIDENT_A,
                            event["artifact_id"], b"c2 beacon config", ["ioc_extraction"], nonce="fixed-nonce")
tok2, r2 = authz.authorize("investigator-alice", sig, challenge, INCIDENT_A,
                            event["artifact_id"], b"c2 beacon config", ["ioc_extraction"], nonce="fixed-nonce")
record(
    "Replay of a used authorization nonce",
    "Attacker captures a previously-issued, already-consumed authorization request",
    "Resubmit an identical authorize() call reusing the same nonce",
    "Second request rejected as a replay",
    f"first={r1}, second={r2}",
    success=(r2 != "REPLAY_DETECTED"),
    property_violated="Authorization freshness / replay protection" if r2 != "REPLAY_DETECTED" else "none",
)

# Attack: cross-incident authorization laundering
registry, authz, inv, event = fresh_env()
challenge = b"challenge-2"
sig = inv.private_key.sign(challenge).hex()
_, r = authz.authorize("investigator-alice", sig, challenge, INCIDENT_B,
                        event["artifact_id"], b"c2 beacon config", ["ioc_extraction"])
record(
    "Cross-incident authorization",
    "Artifact genuinely recorded under Incident A",
    "Investigator (legitimately credentialed on Incident B) requests authorization "
    "for the Incident-A artifact while citing Incident B",
    "Rejected: artifact's recorded incident does not match the claimed incident",
    r,
    success=(r != "INCIDENT_MISMATCH"),
    property_violated="Incident-scoped provenance binding" if r != "INCIDENT_MISMATCH" else "none",
)

# Attack: registry tamper after the fact (attacker with no signing key edits history)
registry, authz, inv, event = fresh_env()
registry.chain[0]["sha256"] = "0" * 64  # tamper without re-signing
valid = registry.verify_chain()
record(
    "Post-hoc provenance record tampering (no signing key)",
    "Attacker gains write access to the registry's storage but not its Ed25519 private key",
    "Directly edit a field (sha256) of an already-signed, already-chained event",
    "Chain/signature verification fails",
    f"verify_chain() == {valid}",
    success=valid,
    property_violated="Tamper-evidence of the append-only log" if valid else "none",
)

# Attack: authenticated investigator requests authorization for an artifact hash
# that was never acquired under ANY incident (arbitrary file, valid identity only)
registry, authz, inv, event = fresh_env()
challenge = b"challenge-3"
sig = inv.private_key.sign(challenge).hex()
_, r = authz.authorize("investigator-alice", sig, challenge, INCIDENT_A,
                        "ART-NEVER-RECORDED", b"arbitrary attacker file", ["static_analysis"])
record(
    "Arbitrary-file submission by a genuinely authenticated investigator",
    "Investigator's own credentials are valid and unphished",
    "Investigator (or malware acting through their session) requests analysis of a "
    "file that was never recorded as acquired during any incident",
    "Rejected: no provenance record exists for this artifact id",
    r,
    success=(r != "NO_PROVENANCE_RECORD"),
    property_violated="Provenance requirement" if r != "NO_PROVENANCE_RECORD" else "none",
)

# Attack: token reuse outside its expiry window
registry, authz, inv, event = fresh_env()
authz.token_ttl = -1  # force immediate expiry for the test
challenge = b"challenge-4"
sig = inv.private_key.sign(challenge).hex()
tok, r = authz.authorize("investigator-alice", sig, challenge, INCIDENT_A,
                          event["artifact_id"], b"c2 beacon config", ["ioc_extraction"])
still_valid = authz.verify_token(tok) if tok else None
record(
    "Use of an expired authorization token",
    "Token was validly issued but its TTL has elapsed",
    "Agent attempts to act on the token after expiry",
    "verify_token() returns False for an expired token",
    f"issued={r}, verify_token_after_expiry={still_valid}",
    success=bool(still_valid),
    property_violated="Token expiration" if still_valid else "none",
)

if __name__ == "__main__":
    for r in results:
        print(f"\n[{'ATTACK SUCCEEDED' if r['attack_succeeded'] else 'blocked'}] {r['attack']}")
        print(f"  precondition : {r['precondition']}")
        print(f"  procedure    : {r['procedure']}")
        print(f"  expected     : {r['expected']}")
        print(f"  observed     : {r['observed']}")
        print(f"  property     : {r['property_violated']}")
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "results"), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "..", "results", "adversarial_tests.json"), "w") as f:
        json.dump(results, f, indent=2)
