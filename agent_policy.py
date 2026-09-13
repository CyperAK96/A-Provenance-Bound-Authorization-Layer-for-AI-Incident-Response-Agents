"""
Simulated AI incident-response agent decision layer.

IMPORTANT LIMITATION (stated explicitly in the paper): this is a
rule-based stand-in for a frontier model's safety policy, not a call
to a real LLM. The sandbox this prototype was built in has no network
egress, so no live model API calls were possible during the sprint.
The rule-based policy is deliberately simple and mirrors the kind of
coarse content-trigger heuristic that commercial safety filters are
reported to use (see Related Work — Hugging Face incident report).
Treat all "agent behavior" numbers as characterizing the AUTHORIZATION
LAYER's effect on a stylized policy, not a claim about any specific
production model. Real-model replication is future work (Limitations).
"""

from dataclasses import dataclass
from typing import Optional

DANGEROUS_KEYWORDS = [
    "reverse shell", "mimikatz", "ransomware", "keylogger", "rootkit",
    "credential dump", "exploit", "backdoor", "c2 beacon", "powershell -enc",
]


@dataclass
class ArtifactCase:
    case_id: str
    category: str            # e.g. "genuine_incident_artifact", "malware", ...
    content_snippet: str
    is_legitimate_incident_artifact: bool   # ground truth: genuinely from a real, open incident
    is_actually_malicious_content: bool     # ground truth: content is dangerous if executed
    requested_task: str      # e.g. "static_analysis" or "execute"


def looks_dangerous(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in DANGEROUS_KEYWORDS)


class Decision:
    ALLOW_ANALYSIS = "ALLOW_ANALYSIS"
    ALLOW_ACTION = "ALLOW_ACTION"       # execution / credential use / network / persistence
    REFUSE = "REFUSE"


def baseline_1_standard_policy(case: ArtifactCase, **kw) -> str:
    """Conventional safety policy: refuse anything that looks dangerous,
    regardless of investigator identity or task. No exception mechanism."""
    if looks_dangerous(case.content_snippet):
        return Decision.REFUSE
    if case.requested_task != "static_analysis" and case.requested_task not in (
        "ioc_extraction", "yara_generation", "attck_mapping",
        "timeline_reconstruction", "config_analysis",
        "malware_classification", "credential_theft_detection",
    ):
        return Decision.REFUSE
    return Decision.ALLOW_ANALYSIS


def baseline_2_no_restriction(case: ArtifactCase, **kw) -> str:
    """No safety restriction at all: agent does whatever is asked."""
    if case.requested_task in ("execute", "credential_use", "network_egress",
                                "lateral_movement", "persistence", "external_write"):
        return Decision.ALLOW_ACTION
    return Decision.ALLOW_ANALYSIS


def baseline_3_auth_only(case: ArtifactCase, authenticated: bool = False, **kw) -> str:
    """Authenticated investigators may request analysis of ANY artifact,
    with no provenance or scope check — the naive exception mechanism."""
    if not authenticated:
        if looks_dangerous(case.content_snippet):
            return Decision.REFUSE
        return Decision.ALLOW_ANALYSIS
    # authenticated: exception applies, no scope enforcement
    if case.requested_task in ("execute", "credential_use", "network_egress",
                                "lateral_movement", "persistence", "external_write"):
        return Decision.ALLOW_ACTION
    return Decision.ALLOW_ANALYSIS


def jail_policy(case: ArtifactCase, jail_authorized: bool = False,
                 authorized_scope: Optional[list] = None, **kw) -> str:
    """
    JAIL-enabled agent: the authorization layer has already checked
    identity + provenance + hash + chain integrity + scope (see
    jail_core.AuthorizationLayer.authorize). The agent policy here
    only needs to enforce: (a) don't act outside the granted scope,
    (b) a JAIL grant is a permission to ANALYZE, never to ACT.
    """
    authorized_scope = authorized_scope or []
    if case.requested_task in ("execute", "credential_use", "network_egress",
                                "lateral_movement", "persistence", "external_write"):
        # JAIL tokens are never issued with action scopes (enforced at
        # issuance in AuthorizationLayer.ALLOWED_ANALYSIS_SCOPES), so any
        # request to act is necessarily a scope-escalation attempt.
        return Decision.REFUSE
    if jail_authorized and case.requested_task in authorized_scope:
        return Decision.ALLOW_ANALYSIS
    # Not JAIL-authorized: fall back to conventional policy
    if looks_dangerous(case.content_snippet):
        return Decision.REFUSE
    return Decision.ALLOW_ANALYSIS
