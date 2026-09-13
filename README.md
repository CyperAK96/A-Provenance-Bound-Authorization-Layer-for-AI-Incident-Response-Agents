# JAIL — Justified Artifact Investigation Layer

Research prototype and reproducibility artifact for the Apart Research
AI Incident Response Sprint 2026 (Track 5: Open Track).

## What this is

A minimal, runnable implementation of a provenance-bound authorization
layer for AI incident-response agents, plus a synthetic benchmark and
adversarial test suite used to evaluate it. See `paper/` (or the
submitted report) for the full writeup, threat model, and discussion
of limitations.

**This is not a production security system.** It is a research
prototype built to test whether the *idea* of provenance-bound,
scope-limited authorization holds up under adversarial pressure.

## Installation

```bash
pip install cryptography matplotlib numpy
```

Python 3.10+.

## Layout

```
/jail
  /protocol           jail_core.py — signed provenance registry, authorization layer
  /prototype          agent_policy.py — 4 agent decision policies (3 baselines + JAIL)
  /benchmark          dataset.py — 27 synthetic labeled artifact cases
  /experiments        run_experiments.py — runs all cases against all 4 conditions
  /attack-scenarios   adversarial_tests.py — 5 targeted protocol-level attacks
  /results            metrics.json, raw_decisions.json, adversarial_tests.json
  /figures            security_utility_tradeoff.png
```

## Running it

```bash
cd experiments && python3 run_experiments.py
cd ../attack-scenarios && python3 adversarial_tests.py
```

## What's real vs. simulated (read this before citing our numbers)

- The provenance registry, Ed25519 signing, hash-chain, replay
  protection, incident revocation, and scope-restricted authorization
  tokens are **real, working code** — not a mock. `verify_chain()`
  genuinely fails when any signed field is altered.
- The "AI agent" is **not** a call to a real LLM. Our sandbox for this
  sprint had no network egress, so no frontier-model API calls were
  possible in the time available. `prototype/agent_policy.py` is a
  small rule-based stand-in for a safety policy (keyword-triggered
  refusal), used only to make legible *what an authorization decision
  changes about downstream behavior*. Treat all "agent" results as
  characterizing the authorization layer, not any production model.
  Replacing the stub with real model calls is the top item for
  follow-up work (see paper, Limitations).
- The benchmark artifacts are short descriptive strings (e.g. "reverse
  shell binary recovered from compromised-host-22"), not real malware,
  exploit code, or credentials. No live payloads were created,
  executed, or distributed as part of this project.

## Datasets

Synthetic only (`benchmark/dataset.py`, n=27 cases across 12
categories). No external or real-world datasets were used.

## Expected output

`run_experiments.py` prints a metrics table and a per-case decision
trace, and writes `results/metrics.json` and `results/raw_decisions.json`.
`adversarial_tests.py` prints pass/fail for 5 targeted attacks and
writes `results/adversarial_tests.json`.

## Limitations

See the paper's Limitations and Dual-Use sections. In short: this
prototype demonstrates that provenance-bound authorization is
*mechanically* distinguishable from identity-only or no-restriction
baselines under the attacks we tested. It does **not** demonstrate
that a real LLM agent would respect a JAIL authorization token rather
than, say, hallucinating one, nor does it demonstrate resistance to a
genuinely stolen (not merely absent) investigator credential, nor does
it address prompt injection contained inside an otherwise legitimately
provenanced artifact.
