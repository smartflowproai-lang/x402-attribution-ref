#!/usr/bin/env node
// Independent verifier for the attribution_ref_v1 vector set (Node + canonicalize, no generator import).
// The expected hashes were produced by a Python implementation, so a PASS here proves byte-for-byte
// cross-library parity (rfc8785 vs canonicalize). The edge registry embedded below is normative
// (spec section 2); the copy inside the vector file is cross-checked and drift is a FAIL.
// Run:  npm install canonicalize ; node runner_node.js [attribution_ref_v1.json]
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import canonicalize from 'canonicalize';

const here = dirname(fileURLToPath(import.meta.url));
const vf = process.argv[2] || join(here, 'attribution_ref_v1.json');
const d = JSON.parse(readFileSync(vf, 'utf-8'));

// Normative edge registry (spec section 2). The vector file must carry an identical copy.
const EDGES = {
  'x402:payto-operator/v1': {
    subject_positions: ['endpoint', 'address', 'key'],
    tier_domain: ['signed_wallet_claim', 'signed_endpoint_claim', 'corroborated', 'catalog_declared', 'heuristic'],
    observation_tiers: ['signed_wallet_claim', 'signed_endpoint_claim'],
    observation_position: 0,
  },
  'x402:facilitator-settlement/v1': {
    subject_positions: ['facilitator', 'address'],
    tier_domain: ['signed_attribution', 'settle_response', 'supported_signer', 'catalog_declared', 'heuristic'],
    observation_tiers: [],
    observation_position: null,
  },
};

const OBS_RE = /^sha256:[0-9a-f]{64}$/;
const EIP155_RE = /^eip155:[1-9][0-9]*:0x[0-9a-fA-F]{40}$/; // canonical decimal chain id
const URL_RE = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(\/[^\s#]*)?$/;
const DIDWEB_RE = /^did:web:[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;
const DIDKEY_RE = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/;
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const BASE_KEYS = ['type', 'value'];
const OBS_KEYS = ['observation', 'observed_at_ms', 'type', 'value'];

class ValidationError extends Error {}

// explicit surrogate scan, no isWellFormed fallback: a lone surrogate must
// reject on every runtime, or old Nodes would silently substitute U+FFFD
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const wellFormed = (s) => !LONE_SURROGATE.test(s);

function validEndpoint(v) {
  if (!v.startsWith('https://')) return false;
  const host = v.slice('https://'.length).split('/', 1)[0];
  if (!host || host.includes('@') || host.includes(':') || host !== host.toLowerCase() || host.includes('..')) return false;
  return URL_RE.test(v);
}

const VALUE_RULES = {
  endpoint: validEndpoint,
  address: (v) => EIP155_RE.test(v),
  key: (v) => DIDKEY_RE.test(v),
  facilitator: (v) => DIDWEB_RE.test(v),
};

const sameKeys = (a, b) => a.length === b.length && a.every((k, i) => k === b[i]);
const prefixed = (o) => 'sha256:' + createHash('sha256').update(Buffer.from(canonicalize(o), 'utf-8')).digest('hex');

function attributionRef(edge, subjectRefs, tier) {
  const e = EDGES[edge];
  if (!e) throw new ValidationError('unknown edge');
  if (!e.tier_domain.includes(tier)) throw new ValidationError("tier outside the edge's closed domain");
  const positions = e.subject_positions;
  if (!Array.isArray(subjectRefs) || subjectRefs.length !== positions.length) throw new ValidationError('arity mismatch');
  const obsTier = e.observation_tiers.includes(tier);
  subjectRefs.forEach((m, i) => {
    if (typeof m !== 'object' || m === null || Array.isArray(m)) throw new ValidationError('member must be an object');
    const keys = Object.keys(m).sort();
    const hasObs = sameKeys(keys, OBS_KEYS);
    if (!hasObs && !sameKeys(keys, BASE_KEYS)) throw new ValidationError('unknown or missing member keys');
    if (m.type !== positions[i]) throw new ValidationError('position type mismatch');
    const v = m.value;
    if (typeof v !== 'string' || !v || !wellFormed(v) || !VALUE_RULES[positions[i]](v)) {
      throw new ValidationError(`member value fails the ${positions[i]} format rule`);
    }
    const allowed = obsTier && i === e.observation_position;
    if (hasObs && !allowed) throw new ValidationError('observation present where forbidden');
    if (allowed && !hasObs) throw new ValidationError('observation required but absent');
    if (hasObs) {
      const ms = m.observed_at_ms;
      if (typeof ms !== 'number' || !Number.isInteger(ms) || !(ms > 0 && ms <= MAX_SAFE_INT)) {
        throw new ValidationError('observed_at_ms must be an integer in (0, 2^53-1]');
      }
      if (typeof m.observation !== 'string' || !OBS_RE.test(m.observation)) {
        throw new ValidationError('observation must be sha256:<64 hex>');
      }
    }
  });
  return prefixed({ edge, subject_refs: subjectRefs, tier });
}

const fails = [];
if (canonicalize(d.edges) !== canonicalize(EDGES)) {
  fails.push('edge registry in the vector file drifts from the normative registry in this runner');
}
for (const v of d.vectors) {
  const got = attributionRef(v.edge, v.subject_refs, v.tier);
  if (got !== v.expected_attribution_ref) fails.push(`${v.id}: ${got} != ${v.expected_attribution_ref}`);
}
for (const n of d.negatives) {
  if (n.must === 'reject') {
    let rejected = false;
    try {
      attributionRef(n.edge, n.subject_refs, n.tier);
    } catch (err) {
      if (!(err instanceof ValidationError)) throw err; // runner bug, not a verdict
      rejected = true;
    }
    if (!rejected) fails.push(`${n.id}: invalid input ACCEPTED (should reject)`);
  } else {
    const got = attributionRef(n.edge, n.subject_refs, n.tier);
    if (got === n.claimed_attribution_ref) fails.push(`${n.id}: tamper NOT detected`);
    else if (n.recomputes_to && got !== n.recomputes_to) fails.push(`${n.id}: ${got} != ${n.recomputes_to}`);
  }
}
const byId = Object.fromEntries(d.vectors.map((v) => [v.id, v.expected_attribution_ref]));
if (byId['po-001'] === byId['po-003']) fails.push('drift-vs-tamper: po-001 == po-003');
if (byId['fa-001'] === byId['fa-002']) fails.push('tier-distinctness: fa-001 == fa-002');

// observation artifacts: frozen bytes must still hash to the bound values
const obsDir = join(dirname(vf), 'observations');
if (existsSync(obsDir)) {
  const vecs = Object.fromEntries(d.vectors.map((v) => [v.id, v]));
  for (const vid of ['po-001', 'po-003']) {
    const p = join(obsDir, `${vid}-402-body.bin`);
    if (!existsSync(p)) { fails.push(`observation artifact missing: ${p}`); continue; }
    const digest = 'sha256:' + createHash('sha256').update(readFileSync(p)).digest('hex');
    const bound = vecs[vid].subject_refs[0].observation;
    if (digest !== bound) fails.push(`${vid}: artifact hash ${digest} != bound observation ${bound}`);
  }
}

const total = d.vectors.length + d.negatives.length;
if (fails.length) {
  console.log('FAIL');
  for (const f of fails) console.log('  ' + f);
  process.exit(1);
}
console.log(`PASS ${total}/${total} -- attribution_ref vectors reproduce byte-for-byte (JS via canonicalize); cross-library parity with the Python runner (rfc8785).`);
