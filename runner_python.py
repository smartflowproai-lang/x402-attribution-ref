#!/usr/bin/env python3
"""Independent verifier for the attribution_ref_v1 vector set.

Imports only the standard library plus a JCS library (rfc8785) -- no generator import.
The edge registry embedded below is normative (spec section 2); the copy inside the
vector file is cross-checked against it and any drift is a FAIL, so the file cannot
quietly validate itself. Recompute is the test. Exit 0 only when all verdicts hold.

Run:  pip install rfc8785 ; python runner_python.py [attribution_ref_v1.json]
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

import rfc8785

# Normative edge registry (spec section 2). The vector file must carry an identical copy.
EDGES = {
    "x402:payto-operator/v1": {
        "subject_positions": ["endpoint", "address", "key"],
        "tier_domain": ["signed_wallet_claim", "signed_endpoint_claim", "corroborated",
                        "catalog_declared", "heuristic"],
        "observation_tiers": ["signed_wallet_claim", "signed_endpoint_claim"],
        "observation_position": 0,
    },
    "x402:facilitator-settlement/v1": {
        "subject_positions": ["facilitator", "address"],
        "tier_domain": ["signed_attribution", "settle_response", "supported_signer",
                        "catalog_declared", "heuristic"],
        "observation_tiers": [],
        "observation_position": None,
    },
}

_OBS_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EIP155_RE = re.compile(r"^eip155:[1-9][0-9]*:0x[0-9a-fA-F]{40}$")  # canonical decimal chain id
_URL_RE = re.compile(r"^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(/[^\s#]*)?$")
_DIDWEB_RE = re.compile(r"^did:web:[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_DIDKEY_RE = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$")
MAX_SAFE_INT = 2**53 - 1
BASE_KEYS = {"type", "value"}
OBS_KEYS = {"type", "value", "observed_at_ms", "observation"}


class ValidationError(Exception):
    """The one exception class that means 'reject, not hashed'."""


def _wf(s):
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _valid_endpoint(v):
    if not v.startswith("https://"):
        return False
    host = v[len("https://"):].split("/", 1)[0]
    if not host or "@" in host or ":" in host or host != host.lower() or ".." in host:
        return False
    return bool(_URL_RE.match(v))


VALUE_RULES = {
    "endpoint": _valid_endpoint,
    "address": lambda v: bool(_EIP155_RE.match(v)),
    "key": lambda v: bool(_DIDKEY_RE.match(v)),
    "facilitator": lambda v: bool(_DIDWEB_RE.match(v)),
}


def attribution_ref(edge, subject_refs, tier):
    if edge not in EDGES:
        raise ValidationError("unknown edge")
    e = EDGES[edge]
    if tier not in e["tier_domain"]:
        raise ValidationError("tier outside the edge's closed domain")
    positions = e["subject_positions"]
    if not isinstance(subject_refs, list) or len(subject_refs) != len(positions):
        raise ValidationError("subject_refs arity mismatch")
    obs_tier = tier in e["observation_tiers"]
    for i, (m, expected) in enumerate(zip(subject_refs, positions)):
        if not isinstance(m, dict):
            raise ValidationError("member must be an object")
        keys = set(m.keys())
        if keys not in (BASE_KEYS, OBS_KEYS):
            raise ValidationError("unknown or missing member keys")
        if m.get("type") != expected:
            raise ValidationError("position type mismatch")
        v = m.get("value")
        if not isinstance(v, str) or not v or not _wf(v) or not VALUE_RULES[expected](v):
            raise ValidationError(f"member value fails the {expected} format rule")
        has_obs = keys == OBS_KEYS
        allowed = obs_tier and i == e["observation_position"]
        if has_obs and not allowed:
            raise ValidationError("observation present where forbidden")
        if allowed and not has_obs:
            raise ValidationError("observation required but absent")
        if has_obs:
            ms = m["observed_at_ms"]
            if isinstance(ms, bool) or not isinstance(ms, int) or not (0 < ms <= MAX_SAFE_INT):
                raise ValidationError("observed_at_ms must be an integer in (0, 2^53-1]")
            if not isinstance(m["observation"], str) or not _OBS_RE.match(m["observation"]):
                raise ValidationError("observation must be sha256:<64 hex>")
    try:
        canon = rfc8785.dumps({"edge": edge, "subject_refs": subject_refs, "tier": tier})
    except Exception as exc:  # canonicalisation failure is a reject, stated explicitly
        raise ValidationError(f"not canonicalizable: {exc}") from exc
    return "sha256:" + hashlib.sha256(canon).hexdigest()


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    vf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "attribution_ref_v1.json")
    d = json.load(open(vf, encoding="utf-8"))
    fails = []

    if d.get("edges") != EDGES:
        fails.append("edge registry in the vector file drifts from the normative registry in this runner")

    for v in d["vectors"]:
        got = attribution_ref(v["edge"], v["subject_refs"], v["tier"])
        if got != v["expected_attribution_ref"]:
            fails.append(f"{v['id']}: {got} != {v['expected_attribution_ref']}")

    for n in d["negatives"]:
        if n["must"] == "reject":
            try:
                attribution_ref(n["edge"], n["subject_refs"], n["tier"])
                fails.append(f"{n['id']}: invalid input ACCEPTED (should reject)")
            except ValidationError:
                pass
        else:
            got = attribution_ref(n["edge"], n["subject_refs"], n["tier"])
            if got == n["claimed_attribution_ref"]:
                fails.append(f"{n['id']}: tamper NOT detected")
            elif n.get("recomputes_to") and got != n["recomputes_to"]:
                fails.append(f"{n['id']}: {got} != {n['recomputes_to']}")

    by_id = {v["id"]: v["expected_attribution_ref"] for v in d["vectors"]}
    if by_id["po-001"] == by_id["po-003"]:
        fails.append("drift-vs-tamper: po-001 == po-003 (drift did not change the reference)")
    if by_id["fa-001"] == by_id["fa-002"]:
        fails.append("tier-distinctness: fa-001 == fa-002")

    # observation artifacts: if observations/ ships next to the vector file,
    # the frozen bytes must still hash to the bound observation values
    obs_dir = os.path.join(os.path.dirname(os.path.abspath(vf)), "observations")
    if os.path.isdir(obs_dir):
        vecs = {v["id"]: v for v in d["vectors"]}
        for vid in ("po-001", "po-003"):
            path = os.path.join(obs_dir, f"{vid}-402-body.bin")
            if not os.path.isfile(path):
                fails.append(f"observation artifact missing: {path}")
                continue
            digest = "sha256:" + hashlib.sha256(open(path, "rb").read()).hexdigest()
            bound = vecs[vid]["subject_refs"][0]["observation"]
            if digest != bound:
                fails.append(f"{vid}: artifact hash {digest} != bound observation {bound}")

    total = len(d["vectors"]) + len(d["negatives"])
    if fails:
        print("FAIL")
        for f in fails:
            print("  " + f)
        return 1
    print(f"PASS {total}/{total} -- attribution_ref vectors reproduce byte-for-byte; "
          "edge + tier + subject order/membership/types + canonical value forms + bound observation "
          "all load-bearing; cross-edge tier, missing/forbidden/partial observation, reorder, drop, "
          "excess arity, decorated member, non-canonical URL/did:web spelling, boolean/overflow "
          "timestamp, lone surrogate and unknown edge all rejected; po-001/po-003 prove drift yields "
          "a new reference while po-neg-obs-tamper proves tampering cannot keep one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
