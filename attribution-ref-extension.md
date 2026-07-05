# `attribution-ref` — Edge-Agnostic Attribution Evidence Envelope

**Status:** Draft extension proposal (v1)
**Relationship:** generalizes the evidence shape landed in #2335 for the facilitator edge (`composite_trust_query_lite_v1` discipline) so that any attribution edge — facilitator↔signer, payTo↔operator, and the next one — is an instance of one construction, not a new scheme per edge. It does **not** recompute the landed `tq-*` refs: those bind a different preimage (`{subject_refs, trust_outcome}` over plain string refs) and stay valid under their own set name. Compatible here means the same canonicalisation pin, the same vector discipline, and one code path across edges.
**Canonicalisation pin:** `urn:x402:canonicalisation:jcs-rfc8785-v1` (RFC 8785 JCS + SHA-256). Arrays stay arrays; no delimiter-joined mini-formats.
**Vectors:** `attribution_ref_v1.json` — 5 positive, 21 negative. Reproduced byte-for-byte by two runners on independent JCS libraries (Python via `rfc8785`, Node via `canonicalize`), PASS 26/26 each, and independently recomputed by a third, from-scratch RFC 8785 implementation (no JCS library) that matched all positive refs, all `must:differ` recomputes and both observation artifact hashes 100% — three-way byte parity. Runners also re-hash the shipped observation artifacts against the bound values.

The key words MUST, MUST NOT, SHOULD, and MAY are per RFC 2119.

---

## 1. Construction

```
attribution_ref = "sha256:" + SHA-256( JCS({ edge, subject_refs, tier }) )
```

One ref per attributed fact. The claim object contains **exactly these three keys** — carrier metadata (ids, annotations, expected values, transport fields) lives outside the hashed object, never inside it. All three fields are byte-load-bearing:

- **`edge`** — which relation is being attributed, from a closed per-version registry (§2). The edge is *inside* the preimage: identical subjects and tier under a different edge cannot collide, even where tier domains overlap (`catalog_declared`, `heuristic` exist on both edges defined here).
- **`subject_refs`** — an ordered JSON array of **typed members** naming the nodes of the edge. Order, membership, member types and member bytes are all load-bearing (JCS canonicalises the array as given; a verifier recomputes with the same parser it uses everywhere else).
- **`tier`** — the confidence rung claimed, a member of the **edge's own closed domain** (§2). A rung the edge cannot earn is rejected, not hashed.

### 1.1 Subject members

```json
{ "type": "endpoint", "value": "https://api.example/x402",
  "observed_at_ms": 1783252462000, "observation": "sha256:…" }
{ "type": "address",  "value": "eip155:8453:0xd779cE46567d21b9918F24f0640cA5Ad6058C893" }
{ "type": "key",      "value": "did:key:z6Mk…" }
{ "type": "facilitator", "value": "did:web:facilitator.example" }
```

- A member carries exactly `{type, value}` — or exactly `{type, value, observed_at_ms, observation}` where the edge requires a bound observation (§3). **Unknown keys are rejected** (vector `po-neg-unknown-member-key`), so two honest emitters cannot produce divergent refs for the same fact by decorating members differently. `observed_at_ms` and `observation` travel together or not at all (`po-neg-partial-obs`).
- `type` is fixed **per position** by the edge definition. The parser is the grammar: a reordered, dropped or duplicated subject fails validation rather than hashing to a plausible reference — and under JCS the array bytes would differ anyway, so an emitter that skips validation still cannot forge a matching ref.
- **Every value form is pinned, because member bytes are load-bearing and spelling must not be emitter's choice:**
  - `endpoint` — canonical URL profile: `https` only, lowercase host, no port (including an explicit `:443`), no fragment, no userinfo; path and query byte-exact as probed, and case-sensitive per RFC 3986. Non-canonical spellings of the same endpoint are rejected, not hashed into a second ref (`po-neg-endpoint-uppercase-host`, `po-neg-endpoint-fragment`).
  - `address` — CAIP-10, closed namespace set in v1: `eip155` only (§6.2 opens others once their canonical form is named). Chain ids are canonical decimal with **no leading zeros** — `eip155:08453` and `eip155:8453` would otherwise mint two refs for one chain (`po-neg-chainid-zeros`). For `eip155`, EIP-55 checksum encoding is the canonical form and normative on the emitter and the attestor. The vector runners enforce shape (`eip155:[1-9][0-9]*:0x<40 hex>`) but not checksum correctness — that needs keccak-256, which sits outside the stdlib-plus-JCS runner envelope; the reference attestor enforces it.
  - `key` — `did:key` (self-certifying, works behind shared proxies — same rationale as the operator-claim draft); runners check syntax (`did:key:z` + base58btc alphabet), cryptographic validity of the key is the attestor's job. `facilitator` — `did:web`, lowercase host-only in v1 (DNS is case-insensitive; `fa-neg-didweb-case`), matching #2335's `kid`; path-bearing did:web is out of scope for v1.
  - All member strings MUST be well-formed Unicode: a lone surrogate is JSON-expressible but not UTF-8-encodable, and an implementation that silently substitutes U+FFFD would collide distinct inputs (`po-neg-lone-surrogate`).
  - `observed_at_ms` is an integer in `(0, 2^53−1]`, so every parser sees the same value; booleans and beyond-IEEE-754-exact integers are rejected (`po-neg-ms-bool`, `po-neg-ms-overflow`).

### 1.2 The JCS-form gate (wire verification)

A verifier consuming a claim off the wire MUST require the claim bytes to already be in JCS form: parse, re-canonicalise, and byte-compare against the input before hashing; mismatch is a reject. This gate — not per-field validation — is what makes the grammar identical across languages: a JSON parser erases number form (`1e3`, `1000.0` and `1000` parse alike), so post-parse checks alone cannot see the difference, while re-canonicalisation restores it byte-for-byte. The vector-file runners validate post-parse values (the file is the fixture, under this repo's control); the gate is normative for anything accepted from outside. A raw-byte wire-fixture set exercising the gate itself (non-canonical number forms, duplicate keys, reordered keys as bytes) is a natural follow-up set and is listed as such in §6.

## 2. Edge registry (v1)

An edge definition declares: the subject sequence (typed positions, fixed arity), the closed tier domain, and which tiers bind an observation. Two edges are registered in v1:

| | `x402:facilitator-settlement/v1` | `x402:payto-operator/v1` |
|---|---|---|
| subjects, in order | `[facilitator, address(signer)]` | `[endpoint, address(payTo), key(operator)]` |
| tier domain | `signed_attribution` · `settle_response` · `supported_signer` · `catalog_declared` · `heuristic` | `signed_wallet_claim` · `signed_endpoint_claim` · `corroborated` · `catalog_declared` · `heuristic` |
| observation | none (chain-state edge) | bound on the `endpoint` member for both `signed_*` rungs; MUST be absent on lower rungs |

The two domains are *why* `tier` cannot be a global scalar: the facilitator rungs and the operator rungs are not higher/lower of one thing, and `signed_wallet_claim` is structurally unreachable wherever the `payTo` wallet is custodial. Declaring the domain per-edge is what lets a verifier reject an over-assertion the edge cannot earn (vector `po-neg-cross-edge-tier`).

The payTo↔operator subject sequence has fixed arity three: the endpoint is always a node of this relation — the claim is served from it and verified against its live 402 — and the payTo address is always named, shared or not. The shared-proxy case (one host fronting 34,148 of 60,644 catalog URLs on Base) is thereby representable instead of unaddressable: the `endpoint` member carries the identity the address cannot.

## 3. Bound observation: network-state rungs freeze what was seen

The facilitator edge recomputes from chain state. `signed_endpoint_claim` rests on a live-402 cross-check — network state — and an endpoint can rotate its `payTo` after the claim. So on the `signed_*` rungs of `x402:payto-operator/v1`, the `endpoint` member MUST bind the probe into the preimage, the same move `execution_ref` makes with `executed_at_ms` and its inputs:

- `observed_at_ms` — when the probe happened (ms epoch, integer).
- `observation` — `sha256:` over the **exact 402 response-body bytes as received**. The raw bytes are kept as a world-readable artifact next to the attestation, so a third party checks *what the observer saw*, not only what it concluded.

A recompute is then against a frozen event, not live state, and the negative-vector line stays sharp:

- **Drift:** a later probe returns different bytes → a genuinely different observation → a legitimately different reference. Vectors `po-001` vs `po-003` are two real probes of one live endpoint, minutes apart; the refs differ and both are honest.
- **Tampering:** an altered claim over the *same* observation cannot keep the claimed reference (`po-neg-obs-tamper`, `po-neg-payto-swap`).
- A `signed_*` claim without an observation, or an observation on a rung that asserts no probe happened (`heuristic`), is rejected, not hashed (`po-neg-obs-drop`, `po-neg-obs-on-heuristic`).

**Consumption.** Freezing an event does not confer freshness: after a payTo rotation, an old claim over an old observation remains a *valid reference to a past event* — that is the design, not a leak, but it means recency is the consumer's judgment. An attestor MUST reject an `observed_at_ms` in the future of its own clock (plus skew) at attestation time; a consumer MUST evaluate `observed_at_ms` against its own recency policy rather than treating any verifiable ref as current. The attestation carrier (not this envelope) is where validity windows live — same split as claim lifetime vs challenge expiry in the operator-claim draft.

## 4. What this envelope is not

It binds the *attributed fact* into one recomputable reference. It does not replace the artifacts that justify the fact: the operator-signed claim document, its challenge, the detached JWS, the countersigned attestation (operator-claim draft), or the facilitator's signed attribution receipt (#2335). Those remain the evidence; an attestation's typed evidence array SHOULD carry the `attribution_ref` alongside content-hashes of the artifacts it was computed from, so the ref composes into #2300-style assertions and the #2332 envelope by reference, like every other ref in this family.

## 5. Vectors

`attribution_ref_v1.json`, same file conventions as `composite_trust_query_lite_v1`:

- **Positive (5):** `po-001` worked example — a real probe of a live x402 endpoint (`verify.smartflowproai.com/audit/order`), observation hash over the exact 402 body bytes (artifact in `observations/`), the endpoint's `accepts[]` declaring the named payTo. The observations are real; the operator key in these vectors is the W3C `did:key` example key (publicly known private key) and is labeled as such in the vector — the vectors exercise the hash construction, not a verified attribution. `po-002` heuristic rung (no observation). `po-003` the drift pair of po-001. `fa-001`/`fa-002` the facilitator edge as an instance of the same envelope (illustrative subjects, #2335's tier list unchanged).
- **Negative (21):** tier swap and payTo swap recompute to different refs; observation tamper cannot keep its ref; missing / forbidden / partial observation, cross-edge tier, reorder, subset-drop, excess arity, decorated member, non-canonical URL and did:web spellings, leading-zero chain id, boolean and overflow timestamps, lone surrogate, out-of-family enum (`TRUSTED` is a `trust_outcome`, not a `tier`), unknown edge, empty list — all rejected, not hashed.
- **Runners:** `runner_python.py` (stdlib + `rfc8785`) and `runner_node.js` (`canonicalize`) each embed the normative edge registry of §2 and FAIL if the copy inside the vector file drifts from it, so the file cannot validate itself; both also re-hash `observations/*.bin` against the bound observation values when the artifacts are present. Both PASS 26/26. A third, from-scratch RFC 8785 implementation (no JCS library) independently reproduced every positive ref, every `must:differ` recompute and both artifact hashes — three-way byte parity across rfc8785, canonicalize and the from-scratch serializer.

## 6. Open questions

1. **Observation coverage for header-only declarations.** The observation freezes response-body bytes — what the reference verifier snapshots today, and sufficient wherever the 402 body carries the declaration (including bodies whose `accepts[]` mirrors the `PAYMENT-REQUIRED` header). A deployment that declares header-only with an empty body would freeze bytes that don't contain the declaration. If that case is real in the wild, the clean fix is a canonical snapshot object — `JCS({status, payment_required_b64, body_b64})` — rather than a second hashing rule; one construction, no per-case forks. Needs a survey before it's worth the added surface.
2. **Multichain address canonicalisation.** EIP-55 pins `eip155:*`; other CAIP-10 namespaces (`solana:*`) need their canonical form named per-namespace before this envelope is used there.
3. **Whether `corroborated` belongs in the payTo↔operator domain at all** — it is observer-local and non-normative in the operator-claim draft; binding it into a content-addressed ref makes an observer-local judgment look portable. It may belong in the attestation, not the envelope. v1 keeps it for cascade completeness; happy to drop it if review says the envelope should carry only emitter-independent rungs.
4. **Host-form `endpoint` subjects.** The thread's framing admitted an endpoint subject as "host or url"; v1 narrows to url-only, because the bound observation is per-resource (a host does not serve a 402). If an edge turns out to need host-granularity subjects, that is a new member type with its own canonical form, not a relaxation of `endpoint`.
5. **Raw-byte wire fixtures for the §1.2 gate.** This set proves value-level and canonicalisation parity; a companion set of raw byte strings (non-canonical number forms, duplicate keys, byte-reordered keys) exercising the parse → re-canonicalise → byte-compare path itself is the natural next set. Also open: an exact percent-encoding and dot-segment policy for URL paths (uppercase hex, no dot-segments is the working assumption of the reference verifier).

---
*Reference verifier for the payTo edge exists and produced the worked-example vectors; both observation artifacts ship with the set. Vectors and runners are self-contained — `pip install rfc8785` / `npm install canonicalize`, run, PASS 26/26 or the set is wrong.*
