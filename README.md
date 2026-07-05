# x402 `attribution-ref` — edge-agnostic attribution evidence envelope

Draft extension + conformance vectors for content-addressed attribution claims in x402, generalizing the evidence shape landed in [x402-foundation/x402#2335](https://github.com/x402-foundation/x402/issues/2335) for the facilitator edge so that any attribution edge is an instance of one construction.

```
attribution_ref = "sha256:" + SHA-256( JCS({ edge, subject_refs, tier }) )
```

- **Spec:** [`attribution-ref-extension.md`](attribution-ref-extension.md)
- **Vectors:** [`attribution_ref_v1.json`](attribution_ref_v1.json) — 5 positive, 21 negative, edge registry included in the file
- **Observation artifacts:** [`observations/`](observations/) — the exact 402 response-body bytes behind the two real probes (`po-001`, `po-003`)
- **Canonicalisation pin:** `urn:x402:canonicalisation:jcs-rfc8785-v1` (RFC 8785 JCS + SHA-256)

## Recompute it yourself

```bash
pip install rfc8785
python runner_python.py          # PASS 26/26

npm install canonicalize
node runner_node.js              # PASS 26/26
```

Each runner embeds the normative edge registry and FAILs if the copy inside the vector file drifts from it, so the file cannot validate itself; both also re-hash `observations/*.bin` against the bound observation values. Every expected hash has been reproduced by three distinct serializers — `rfc8785` (Python), `canonicalize` (Node), and a from-scratch RFC 8785 implementation with no JCS library — byte for byte. Address values are shape-checked (`eip155`, canonical decimal chain id, `0x` + 40 hex); EIP-55 checksum correctness is normative on the emitter and enforced by the reference attestor, not by this suite (keccak-256 sits outside the stdlib envelope).

The observations are real: `po-001` and `po-003` are two live probes of an x402 endpoint minutes apart (the operator key in the vectors is the W3C did:key example key, labeled illustrative — the vectors prove the hash construction, not a verified attribution). Verify the frozen artifacts:

```bash
shasum -a 256 observations/po-001-402-body.bin   # 575ad15e… (== po-001 observation)
shasum -a 256 observations/po-003-402-body.bin   # 92c7469a… (== po-003 observation)
```

Same endpoint, same subjects, different bytes → legitimately different references. That is the drift/tamper line the vectors hold: drift changes the observation (`po-001` vs `po-003`), tampering cannot keep its reference (`po-neg-obs-tamper`).

## File conventions

Follows [`algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors) (`composite_trust_query_lite_v1`): one JSON set with `vectors` / `negatives` / `invariants`, negative families named, `must: differ` carries a computed `recomputes_to`, `must: reject` is rejected before hashing.

## Status

Draft for review in #2335. The edge registry, the `corroborated` rung, and observation coverage for header-only 402s are open questions — see spec §6.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This work builds on the AlgoVoi canonicalisation substrate ([`algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors), `urn:x402:canonicalisation:jcs-rfc8785-v1`), Apache-2.0. Upstream attribution and NOTICE are carried forward in [`NOTICE`](NOTICE).
