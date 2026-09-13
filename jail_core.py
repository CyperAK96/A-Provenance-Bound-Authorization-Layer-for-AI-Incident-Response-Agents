"""
JAIL — Justified Artifact Investigation Layer
Core protocol: identity, signed append-only provenance registry,
scoped authorization tokens.

This is a research prototype, not production code. Ed25519 keys are
generated in-process for reproducibility; a real deployment would use
an HSM-backed root of trust (see paper, Section 3 / Cryptographic
Design).
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: dict) -> bytes:
    """Deterministic serialization for signing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Signer:
    """Wraps an Ed25519 keypair for a role (registry, IdP, investigator...)."""

    def __init__(self, name: str):
        self.name = name
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, payload: dict) -> str:
        sig = self.private_key.sign(canonical(payload))
        return sig.hex()

    def verify(self, payload: dict, signature_hex: str) -> bool:
        try:
            self.public_key.verify(bytes.fromhex(signature_hex), canonical(payload))
            return True
        except InvalidSignature:
            return False


class TrustAnchorCompromisedError(Exception):
    pass


class ProvenanceRegistry:
    """
    Append-only, hash-chained, signed log of artifact acquisition events.

    Trust assumption (explicit): the private key held by `self.signer`
    (the "registry" role) is trusted. Anyone who steals this key can
    forge history. This is the single trust anchor JAIL depends on for
    provenance integrity — see Threat Model, Attacker D.
    """

    def __init__(self, signer: Signer):
        self.signer = signer
        self.chain: list[dict] = []

    def _prev_hash(self) -> str:
        if not self.chain:
            return "0" * 64
        last = {k: v for k, v in self.chain[-1].items() if k != "signature"}
        return sha256_hex(canonical(last))

    def record_acquisition(
        self,
        incident_id: str,
        artifact_bytes: bytes,
        source_system: str,
        investigator_id: str,
        acquisition_method: str,
        parent_artifact_id: Optional[str] = None,
    ) -> dict:
        artifact_id = "ART-" + uuid.uuid4().hex[:8]
        event = {
            "event_id": "E-" + uuid.uuid4().hex[:8],
            "incident_id": incident_id,
            "artifact_id": artifact_id,
            "sha256": sha256_hex(artifact_bytes),
            "timestamp": time.time(),
            "source_system": source_system,
            "investigator_id": investigator_id,
            "acquisition_method": acquisition_method,
            "parent_artifact_id": parent_artifact_id,
            "prev_hash": self._prev_hash(),
        }
        event["signature"] = self.signer.sign(event)
        self.chain.append(event)
        return event

    def verify_chain(self) -> bool:
        """Detect tampering: recompute link hashes and check every signature."""
        prev = "0" * 64
        for event in self.chain:
            body = {k: v for k, v in event.items() if k != "signature"}
            if body["prev_hash"] != prev:
                return False
            unsigned = {k: v for k, v in event.items() if k != "signature"}
            if not self.signer.verify(unsigned, event["signature"]):
                return False
            prev = sha256_hex(canonical(unsigned))
        return True

    def lookup(self, artifact_id: str) -> Optional[dict]:
        for event in reversed(self.chain):
            if event["artifact_id"] == artifact_id:
                return event
        return None

    def revoke_incident(self, incident_id: str):
        """Simulates SOC closing/revoking an incident (Attacker scenario: expired incident)."""
        if not hasattr(self, "_revoked"):
            self._revoked = set()
        self._revoked.add(incident_id)

    def is_incident_revoked(self, incident_id: str) -> bool:
        return incident_id in getattr(self, "_revoked", set())


@dataclass
class AuthorizationToken:
    token_id: str
    artifact_id: str
    incident_id: str
    investigator_id: str
    scope: list        # e.g. ["static_analysis", "ioc_extraction"]
    issued_at: float
    expires_at: float
    nonce: str
    signature: str = ""

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return now > self.expires_at


class AuthorizationLayer:
    """
    Issues narrowly-scoped, time-limited, single-use authorization tokens
    ONLY when identity, provenance, and integrity all check out
    (Model C in the paper: identity + provenance + task authorization).
    """

    ALLOWED_ANALYSIS_SCOPES = {
        "static_analysis", "ioc_extraction", "yara_generation",
        "attck_mapping", "timeline_reconstruction", "config_analysis",
        "malware_classification", "credential_theft_detection",
    }
    FORBIDDEN_SCOPES = {
        "execute", "credential_use", "network_egress",
        "lateral_movement", "persistence", "external_write",
    }

    def __init__(self, registry: ProvenanceRegistry, idp_signer: Signer,
                 token_ttl_seconds: int = 900):
        self.registry = registry
        self.idp_signer = idp_signer
        self.token_ttl = token_ttl_seconds
        self._used_nonces = set()
        self._issued_tokens: dict[str, AuthorizationToken] = {}
        self._valid_investigators: dict[str, Signer] = {}

    def register_investigator(self, investigator_id: str) -> Signer:
        signer = Signer(investigator_id)
        self._valid_investigators[investigator_id] = signer
        return signer

    def authenticate(self, investigator_id: str, credential_signature: str,
                      challenge: bytes) -> bool:
        signer = self._valid_investigators.get(investigator_id)
        if signer is None:
            return False
        try:
            signer.public_key.verify(bytes.fromhex(credential_signature), challenge)
            return True
        except InvalidSignature:
            return False

    def authorize(
        self,
        investigator_id: str,
        credential_signature: str,
        challenge: bytes,
        incident_id: str,
        artifact_id: str,
        submitted_artifact_bytes: bytes,
        requested_scope: list,
        nonce: Optional[str] = None,
    ):
        """
        Returns (token_or_None, reason). Every rejection reason is explicit
        so failures are auditable (needed for the metrics in Section 4).
        """
        nonce = nonce or uuid.uuid4().hex

        # 1. Identity
        if not self.authenticate(investigator_id, credential_signature, challenge):
            return None, "AUTH_FAILED"

        # 2. Replay protection
        if nonce in self._used_nonces:
            return None, "REPLAY_DETECTED"

        # 3. Provenance existence + incident match
        record = self.registry.lookup(artifact_id)
        if record is None:
            return None, "NO_PROVENANCE_RECORD"
        if record["incident_id"] != incident_id:
            return None, "INCIDENT_MISMATCH"
        if self.registry.is_incident_revoked(incident_id):
            return None, "INCIDENT_REVOKED"

        # 4. Integrity: submitted bytes must match recorded hash exactly
        submitted_hash = sha256_hex(submitted_artifact_bytes)
        if submitted_hash != record["sha256"]:
            return None, "HASH_MISMATCH"

        # 5. Chain integrity (detects registry tampering)
        if not self.registry.verify_chain():
            return None, "REGISTRY_TAMPER_DETECTED"

        # 6. Scope validation — reject anything outside the analysis allow-list
        scope = set(requested_scope)
        if not scope.issubset(self.ALLOWED_ANALYSIS_SCOPES):
            return None, "SCOPE_REJECTED"
        if scope & self.FORBIDDEN_SCOPES:
            return None, "SCOPE_REJECTED"

        self._used_nonces.add(nonce)
        now = time.time()
        token = AuthorizationToken(
            token_id="TOK-" + uuid.uuid4().hex[:8],
            artifact_id=artifact_id,
            incident_id=incident_id,
            investigator_id=investigator_id,
            scope=sorted(scope),
            issued_at=now,
            expires_at=now + self.token_ttl,
            nonce=nonce,
        )
        payload = asdict(token)
        payload.pop("signature")
        token.signature = self.idp_signer.sign(payload)
        self._issued_tokens[token.token_id] = token
        return token, "OK"

    def verify_token(self, token: AuthorizationToken) -> bool:
        payload = asdict(token)
        payload.pop("signature")
        if not self.idp_signer.verify(payload, token.signature):
            return False
        if token.is_expired():
            return False
        return True
