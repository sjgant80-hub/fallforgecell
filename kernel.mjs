// Veridia (fallforgecell) — the cell kernel. Veridia is the 1D→ line/triangle organ of the FallForge
// estate: it COMPOSES proven, owned task-nodes minted by fallforgemint (the 0D foundry) across gated
// seams, and cross-checks them so the composition is not just SAFE but CORRECT. It never mints models
// and never touches the foundry — it consumes what the foundry produced (outputs + signed scorecards).
//
// This file is the pure, total core: no I/O, garbage in → { ok:false, why }, never a throw. The SHA-256
// and canonical-JSON pair are vendored verbatim from the proven fallforgemint kernel (witness-clean) so
// the receipts chain in the same format. Everything below the primitives is Veridia's own gated logic.

const isStr = (v) => typeof v === 'string';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;

// ── SHA-256 + canonical JSON (vendored verbatim from fallforgemint — the same proven pair) ───────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── agreement primitive: do two node answers say the same thing? (normalised, not brittle) ───────────
// Numbers compare by value (0 == 0.00 == "0"), strings by whitespace/case-normalised equality. This is
// what the triangle's cross-check is built on: "agree" must survive formatting noise but catch real
// difference (a wrong supplier, a 10x total).
export function normValue(v) {
  if (isNum(v)) return { kind: 'num', v };
  if (typeof v === 'boolean') return { kind: 'bool', v };
  if (v === null || v === undefined) return { kind: 'nul', v: null };
  if (isStr(v)) {
    const t = v.trim();
    if (t !== '' && Number.isFinite(Number(t))) return { kind: 'num', v: Number(t) };
    const iso = t.match(/^(\d{4}-\d{2}-\d{2})(?:[t ].*)?$/i);   // 2023-01-15 == 2023-01-15T00:00:00Z
    if (iso) return { kind: 'date', v: iso[1] };
    return { kind: 'str', v: t.toLowerCase().replace(/\s+/g, ' ') };
  }
  return { kind: 'other', v: canon(v) };
}

/** agree(a,b) — do two node answers say the same thing, after normalising away formatting noise? */
export function agree(a, b) {
  const na = normValue(a), nb = normValue(b);
  return na.kind === nb.kind && na.v === nb.v;
}

// ── the triangle: cross-check independent nodes so a composition is CORRECT, not just SAFE ──────────
// N independent nodes answer the SAME task; we adjudicate PER FIELD. The load-bearing rule (Kar and I
// both landed on it): agreement among IDENTICAL nodes is NOT evidence — three clones tell the same
// confident lie three times. So the panel MUST be independent (distinct model fingerprints) or the
// cross-check is refused, and the receipt records the fingerprints as proof it was real. A triangle of
// clones is theatre, and Veridia says so.

export const MIN_PANEL = 3;   // three to break a tie; two can only disagree

/** panelIndependent(fingerprints) — the panel must be distinct models, else agreement proves nothing. */
export function panelIndependent(fingerprints) {
  if (!Array.isArray(fingerprints) || fingerprints.length < MIN_PANEL) return { ok: false, why: 'a cross-check needs at least ' + MIN_PANEL + ' nodes' };
  for (const f of fingerprints) if (!isStr(f) || f.length === 0) return { ok: false, why: 'every node needs a model fingerprint' };
  const uniq = new Set(fingerprints);
  if (uniq.size !== fingerprints.length) return { ok: true, independent: false, why: 'the panel has duplicate models — agreement among identical nodes is not verification' };
  return { ok: true, independent: true };
}

/** adjudicateField(values) — one field across the panel → { verdict, value, votes }. */
export function adjudicateField(values) {
  if (!Array.isArray(values) || values.length < MIN_PANEL) return { ok: false, why: 'need at least ' + MIN_PANEL + ' values to adjudicate' };
  const groups = [];   // [{ rep, idx:[...] }]
  values.forEach((v, i) => {
    const g = groups.find((x) => agree(x.rep, v));
    if (g) g.idx.push(i); else groups.push({ rep: v, idx: [i] });
  });
  groups.sort((a, b) => b.idx.length - a.idx.length);
  const top = groups[0], n = values.length;
  let verdict;
  if (top.idx.length === n) verdict = 'UNANIMOUS';
  else if (top.idx.length * 2 > n) verdict = 'MAJORITY';
  else verdict = 'SPLIT';
  const dissent = groups.slice(1).flatMap((g) => g.idx);
  return { ok: true, verdict, value: verdict === 'SPLIT' ? null : top.rep, agreeCount: top.idx.length, of: n, agreedBy: top.idx, dissent, escalate: verdict === 'SPLIT' };
}

/** adjudicate(answers, fingerprints) — the whole record, field by field. Refuses a non-independent panel. */
export function adjudicate(answers, fingerprints) {
  if (!Array.isArray(answers)) return { ok: false, why: 'answers must be a list' };
  if (answers.length < MIN_PANEL) return { ok: false, why: 'need at least ' + MIN_PANEL + ' answers' };
  for (const a of answers) if (!isObj(a)) return { ok: false, why: 'each answer must be an object of fields' };
  if (!Array.isArray(fingerprints)) return { ok: false, why: 'fingerprints must be a list' };
  if (fingerprints.length !== answers.length) return { ok: false, why: 'need one model fingerprint per answer' };
  const ind = panelIndependent(fingerprints);
  if (!ind.ok) return ind;
  if (!ind.independent) return { ok: true, independent: false, why: ind.why, accepted: {}, escalate: [], fields: {}, verdict: 'REFUSED' };
  const keys = [...new Set(answers.flatMap((a) => Object.keys(a)))].sort();
  if (keys.length === 0) return { ok: false, why: 'the answers have no fields to adjudicate' };
  const fields = {}, accepted = {}, escalate = [];
  for (const k of keys) {
    const f = adjudicateField(answers.map((a) => a[k]));
    if (!f.ok) return f;
    fields[k] = f;
    if (f.escalate) escalate.push(k); else accepted[k] = f.value;
  }
  // overall verdict is the worst field: any SPLIT ⇒ SPLIT; else any MAJORITY ⇒ MAJORITY; else UNANIMOUS
  let verdict = 'UNANIMOUS';
  for (const k of keys) {
    if (fields[k].verdict === 'SPLIT') { verdict = 'SPLIT'; break; }
    if (fields[k].verdict === 'MAJORITY') verdict = 'MAJORITY';
  }
  return { ok: true, independent: true, accepted, escalate, fields, verdict, panel: fingerprints.length };
}

// ── the cross-check receipt: a tamper-evident record of a triangle's verdict, binding its panel ──────
// It records the panel (fingerprints = proof of independence; node receipt hashes = the chain back to
// each node's fallforgemint scorecard), the per-field verdicts, and what escalated. Self-hashed, and
// signable like the scorecard. HONEST: it proves the panel agreed and was independent, NOT that they
// were right — a unanimous panel can be unanimously wrong; that's why SPLIT fields go to a human.
export function crosscheckReceipt(input) {
  if (!isObj(input)) return { ok: false, why: 'crosscheckReceipt takes an object' };
  const { taskHash, createdAt, nodes } = input;
  if (!isStr(taskHash)) return { ok: false, why: 'taskHash must be a string' };
  if (taskHash.length !== 64 || !HEX.test(taskHash)) return { ok: false, why: 'taskHash must be a 64-character hex hash' };
  if (!isStr(createdAt)) return { ok: false, why: 'the receipt needs a createdAt timestamp' };
  if (createdAt.length === 0) return { ok: false, why: 'the receipt needs a non-empty createdAt timestamp' };
  if (!Array.isArray(nodes)) return { ok: false, why: 'nodes must be a list' };
  if (nodes.length < MIN_PANEL) return { ok: false, why: 'a cross-check needs at least ' + MIN_PANEL + ' nodes' };
  const fingerprints = [], answers = [];
  for (const [i, nd] of nodes.entries()) {
    const n = i + 1;
    if (!isObj(nd)) return { ok: false, why: 'node ' + n + ' must be an object' };
    if (!isStr(nd.fingerprint)) return { ok: false, why: 'node ' + n + ' needs a model fingerprint' };
    if (nd.fingerprint.length === 0) return { ok: false, why: 'node ' + n + ' has an empty model fingerprint' };
    if (!isStr(nd.receiptHash)) return { ok: false, why: 'node ' + n + ' needs a receipt hash' };
    if (nd.receiptHash.length !== 64 || !HEX.test(nd.receiptHash)) return { ok: false, why: 'node ' + n + ' needs a 64-character hex receipt hash' };
    if (!isObj(nd.answer)) return { ok: false, why: 'node ' + n + ' needs an answer object' };
    fingerprints.push(nd.fingerprint);
    answers.push(nd.answer);
  }
  const adj = adjudicate(answers, fingerprints);
  if (!adj.ok) return adj;
  if (!adj.independent) return { ok: false, why: adj.why };   // a clone panel cannot issue a receipt
  const fieldVerdicts = {};
  for (const k of Object.keys(adj.fields)) fieldVerdicts[k] = { verdict: adj.fields[k].verdict, agreeCount: adj.fields[k].agreeCount, of: adj.fields[k].of };
  const body = {
    v: 1,
    kind: 'veridia-crosscheck',
    taskHash, createdAt,
    panel: nodes.map((nd) => ({ fingerprint: nd.fingerprint, receiptHash: nd.receiptHash })),
    verdict: adj.verdict,
    fields: fieldVerdicts,
    accepted: adj.accepted,
    escalate: adj.escalate,
    scope: "A cross-check of INDEPENDENT nodes on one task. It records that the panel was independent (distinct models) and how they voted, field by field. It proves agreement, not truth — a unanimous panel can still be unanimously wrong; SPLIT fields escalate to a human.",
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, receipt: { ...body, hash: h.hash } };
}

/** crosscheckSignable(receipt) — the exact canonical bytes an Ed25519 signature covers (receipt minus signature). */
export function crosscheckSignable(receipt) {
  if (!isObj(receipt)) return { ok: false, why: 'not a veridia cross-check receipt' };
  if (receipt.kind !== 'veridia-crosscheck') return { ok: false, why: 'not a veridia cross-check receipt' };
  if (!isStr(receipt.hash)) return { ok: false, why: 'the receipt has no hash' };
  const body = { ...receipt };
  delete body.signature;
  return { ok: true, payload: canon(body) };
}

/** verifyCrosscheckReceipt(r) — matches its own hash AND the panel is genuinely independent. */
export function verifyCrosscheckReceipt(r) {
  if (!isObj(r)) return { ok: false, why: 'not a veridia cross-check receipt' };
  if (r.kind !== 'veridia-crosscheck') return { ok: false, why: 'not a veridia cross-check receipt' };
  if (!isStr(r.hash)) return { ok: false, why: 'the receipt has no hash' };
  const body = { ...r };
  delete body.hash;
  delete body.signature;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== r.hash) return { ok: true, valid: false, why: 'the receipt does not match its own fingerprint — it was changed after it was issued' };
  if (!Array.isArray(r.panel)) return { ok: true, valid: false, why: 'the receipt has no panel' };
  if (r.panel.length < MIN_PANEL) return { ok: true, valid: false, why: 'the panel is too small to be a cross-check' };
  const fps = r.panel.map((p) => (isObj(p) ? p.fingerprint : null));
  if (new Set(fps).size !== fps.length) return { ok: true, valid: false, why: 'the panel is not independent — duplicate models, so the agreement is not verification' };
  return { ok: true, valid: true, why: 'cross-check intact' };
}

// ── the tetrahedron: compose cross-checks into a verified PROCESS ─────────────────────────────────
// The triangle proves ONE answer correct. The tetra proves a PROCESS correct: a pipeline where every
// step is its own triangle cross-check, and each step BINDS the previous step's ACCEPTED output (not
// just declares a link — inputHash = sha256(canon(prior.accepted)), so you cannot swap the input).
// A step that escalates a field does NOT silently halt the process (that would bin the accepted work)
// and is NOT silently ignored (that would hide the gap): the pipeline continues on the accepted fields
// and the composite verdict is FLAGGED, recording exactly which step needs a human. A broken/invalid
// step or a broken seam cannot issue a pipeline receipt at all. Honest: it proves the process was
// cross-checked and correctly chained, NOT that the final answer is true.
export const MIN_STEPS = 2;   // one step is just a triangle; a pipeline is two or more

export function composePipeline(steps, createdAt) {
  if (!Array.isArray(steps)) return { ok: false, why: 'steps must be a list' };
  if (steps.length < MIN_STEPS) return { ok: false, why: 'a pipeline needs at least ' + MIN_STEPS + ' steps' };
  if (!isStr(createdAt)) return { ok: false, why: 'the pipeline needs a createdAt timestamp' };
  if (createdAt.length === 0) return { ok: false, why: 'the pipeline needs a non-empty createdAt timestamp' };
  const rows = [];
  for (const [i, st] of steps.entries()) {
    const n = i + 1;
    if (!isObj(st)) return { ok: false, why: 'step ' + n + ' must be an object' };
    if (!isStr(st.name)) return { ok: false, why: 'step ' + n + ' needs a name' };
    if (st.name.trim().length === 0) return { ok: false, why: 'step ' + n + ' needs a non-empty name' };
    if (!isObj(st.receipt)) return { ok: false, why: 'step ' + n + ' needs a cross-check receipt' };
    const v = verifyCrosscheckReceipt(st.receipt);
    if (!v.ok) return { ok: false, why: 'step ' + n + ' is not a cross-check receipt' };
    if (!v.valid) return { ok: false, why: 'step ' + n + ' has an invalid receipt: ' + v.why };
    // the seam: step 1 has no input; every later step must have consumed the PRIOR step's accepted output
    if (i === 0) {
      if (st.inputHash !== null && st.inputHash !== undefined) return { ok: false, why: 'the first step has no input to bind' };
    } else {
      const priorAccepted = sha256(canon(steps[i - 1].receipt.accepted || {}));
      if (!priorAccepted.ok) return { ok: false, why: priorAccepted.why };
      if (!isStr(st.inputHash)) return { ok: false, why: 'step ' + n + ' must bind its input' };
      if (st.inputHash !== priorAccepted.hash) return { ok: false, why: 'step ' + n + ' did not consume step ' + (n - 1) + "'s accepted output — the seam is broken" };
    }
    rows.push({ name: st.name.trim(), receiptHash: st.receipt.hash, verdict: st.receipt.verdict, escalate: Array.isArray(st.receipt.escalate) ? st.receipt.escalate.slice() : [] });
  }
  let hasSplit = false, hasMajority = false;
  for (const r of rows) {
    if (r.verdict === 'SPLIT') hasSplit = true;
    if (r.verdict === 'MAJORITY') hasMajority = true;
  }
  const verdict = hasSplit ? 'FLAGGED' : (hasMajority ? 'MAJORITY' : 'CLEAN');
  const body = {
    v: 1,
    kind: 'veridia-pipeline',
    steps: rows,
    verdict, createdAt,
    scope: "A verified process: each step is an independent cross-check, and each step consumed the previous step's ACCEPTED output (the seam is bound, not just declared). CLEAN = every step's panel agreed; MAJORITY = some step needed a majority; FLAGGED = a step escalated a field to a human. It proves the process was cross-checked and correctly chained, not that the final answer is true.",
  };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, receipt: { ...body, hash: h.hash } };
}

/** pipelineSignable(receipt) — the exact canonical bytes an Ed25519 signature covers (minus signature). */
export function pipelineSignable(receipt) {
  if (!isObj(receipt)) return { ok: false, why: 'not a veridia pipeline receipt' };
  if (receipt.kind !== 'veridia-pipeline') return { ok: false, why: 'not a veridia pipeline receipt' };
  if (!isStr(receipt.hash)) return { ok: false, why: 'the receipt has no hash' };
  const body = { ...receipt };
  delete body.signature;
  return { ok: true, payload: canon(body) };
}

/** verifyPipelineReceipt(r) — matches its own hash AND the composite verdict matches its steps. */
export function verifyPipelineReceipt(r) {
  if (!isObj(r)) return { ok: false, why: 'not a veridia pipeline receipt' };
  if (r.kind !== 'veridia-pipeline') return { ok: false, why: 'not a veridia pipeline receipt' };
  if (!isStr(r.hash)) return { ok: false, why: 'the receipt has no hash' };
  const body = { ...r };
  delete body.hash;
  delete body.signature;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== r.hash) return { ok: true, valid: false, why: 'the receipt does not match its own fingerprint — it was changed after it was issued' };
  if (!Array.isArray(r.steps)) return { ok: true, valid: false, why: 'the receipt has no steps' };
  if (r.steps.length < MIN_STEPS) return { ok: true, valid: false, why: 'a pipeline needs at least ' + MIN_STEPS + ' steps' };
  // the composite verdict must match the steps — a receipt claiming CLEAN over a FLAGGED step is a lie
  let hasSplit = false, hasMajority = false;
  for (const s of r.steps) {
    if (!isObj(s)) return { ok: true, valid: false, why: 'a step is malformed' };
    if (s.verdict === 'SPLIT') hasSplit = true;
    if (s.verdict === 'MAJORITY') hasMajority = true;
  }
  const expected = hasSplit ? 'FLAGGED' : (hasMajority ? 'MAJORITY' : 'CLEAN');
  if (r.verdict !== expected) return { ok: true, valid: false, why: 'the pipeline verdict does not match its steps' };
  return { ok: true, valid: true, why: 'pipeline intact' };
}
