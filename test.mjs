import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MIN_PANEL, MIN_STEPS, MIN_UNITS,
  sha256, canon, normValue, agree,
  panelIndependent, adjudicateField, adjudicate,
  crosscheckReceipt, crosscheckSignable, verifyCrosscheckReceipt,
  composePipeline, pipelineSignable, verifyPipelineReceipt,
  merkleRoot, composeDepartment, departmentSignable, verifyDepartmentReceipt,
} from './kernel.mjs';

test('sha256 + canon: vendored proven pair still holds (FIPS-pinned, order-blind)', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256(7).ok, false);
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ x: 5 }), canon({ x: '5' }));
  assert.notEqual(canon({ x: null }), canon({ x: 0 }));
  // each primitive serialises to its exact form (pins the || chain in canon)
  assert.equal(canon(5), '5');
  assert.equal(canon(true), 'true');
  assert.equal(canon(false), 'false');
  assert.equal(canon(null), 'null');
  assert.equal(canon('x'), '"x"');
});

test('normValue + agree: agreement is by value, not by formatting', () => {
  assert.equal(agree(0, '0'), true);
  assert.equal(agree(0, '0.00'), true);           // numeric string equals number
  assert.equal(agree('ACME', ' acme '), true);    // case + whitespace normalised
  assert.equal(agree('2023-01-15', '2023-01-15T00:00:00Z'), true);   // ISO date prefix
  assert.equal(agree('2023-01-15', 'jan 15 2023'), false);          // unknown format → safe disagree
  assert.equal(agree('refund', 'delivery'), false);
  assert.equal(agree(null, undefined), true);     // both absent = agree they're absent
  assert.equal(agree(1, 2), false);
  assert.equal(agree(true, 'true'), false);       // bool vs string are distinct kinds
  assert.equal(normValue('  Hi  There ').v, 'hi there');
  assert.equal(normValue('2020-12-31T09:00').kind, 'date');
  assert.notEqual(normValue(NaN).kind, 'num');       // the vendored isNum rejects NaN
  assert.notEqual(normValue(Infinity).kind, 'num');  // and Infinity — never counts as a value
});

test('panelIndependent: distinct = independent, duplicates = theatre, <3 refused', () => {
  assert.equal(panelIndependent(['a', 'b', 'c']).independent, true);
  const dup = panelIndependent(['a', 'a', 'c']);
  assert.equal(dup.ok, true);
  assert.equal(dup.independent, false);            // three clones agreeing is NOT verification
  assert.equal(panelIndependent(['a', 'b']).ok, false);        // fewer than MIN_PANEL
  assert.equal(panelIndependent(['a', 'b', '']).ok, false);    // empty fingerprint
  assert.equal(panelIndependent('nope').ok, false);
  assert.equal(panelIndependent([1, 2, 3]).ok, false);         // non-string
  assert.equal(MIN_PANEL, 3);
});

test('adjudicateField: unanimous / majority / split, exact boundaries', () => {
  assert.equal(adjudicateField(['a', 'a', 'a']).verdict, 'UNANIMOUS');
  const maj = adjudicateField(['a', 'a', 'b']);
  assert.equal(maj.verdict, 'MAJORITY');
  assert.equal(maj.value, 'a');
  assert.equal(maj.agreeCount, 2);
  assert.deepEqual(maj.dissent, [2]);
  assert.equal(maj.escalate, false);
  const split = adjudicateField(['a', 'b', 'c']);
  assert.equal(split.verdict, 'SPLIT');
  assert.equal(split.value, null);
  assert.equal(split.escalate, true);
  // boundaries that kill the count mutants:
  assert.equal(adjudicateField(['a', 'a', 'a', 'a']).verdict, 'UNANIMOUS'); // n/n (kills === → >=/>)
  assert.equal(adjudicateField(['a', 'a', 'a', 'b']).verdict, 'MAJORITY');  // 3 of 4
  assert.equal(adjudicateField(['a', 'a', 'b', 'b']).verdict, 'SPLIT');     // 2-2 tie, no majority (kills *2 > n)
  assert.equal(adjudicateField([0, '0.00', '0']).verdict, 'UNANIMOUS');     // normalised agreement
  assert.equal(adjudicateField(['a', 'a']).ok, false);         // < MIN_PANEL
  assert.equal(adjudicateField('nope').ok, false);
});

const FPS = ['llama3.2:1b#a', 'qwen2.5:0.5b#b', 'gemma2:2b#c'];

test('adjudicate: per-field, worst-field overall, refuses a clone panel', () => {
  const answers = [
    { supplier: 'ACME', total: 100, date: '2023-01-15' },
    { supplier: 'ACME', total: 100, date: '2023-01-15T00:00:00Z' },
    { supplier: 'ACME', total: 1000, date: '2023-02-01' },   // node 3 differs on total AND date
  ];
  const r = adjudicate(answers, FPS);
  assert.equal(r.ok, true);
  assert.equal(r.independent, true);
  assert.equal(r.fields.supplier.verdict, 'UNANIMOUS');
  assert.equal(r.fields.total.verdict, 'MAJORITY');
  assert.equal(r.accepted.total, 100);              // majority value, not the outlier 1000
  assert.equal(r.fields.date.verdict, 'MAJORITY');  // two ISO-equal dates beat the third
  assert.equal(r.accepted.supplier, 'ACME');
  assert.equal(r.escalate.length, 0);               // nothing SPLIT here
  assert.equal(r.verdict, 'MAJORITY');              // worst field is a majority

  // a SPLIT field escalates only itself and is NOT in accepted
  const sp = adjudicate([{ x: 'a' }, { x: 'b' }, { x: 'c' }], FPS);
  assert.deepEqual(sp.escalate, ['x']);
  assert.equal(sp.verdict, 'SPLIT');
  assert.equal('x' in sp.accepted, false);

  // all fields unanimous → overall UNANIMOUS
  assert.equal(adjudicate([{ x: 'a' }, { x: 'a' }, { x: 'a' }], FPS).verdict, 'UNANIMOUS');

  // a clone panel is REFUSED even when all three agree
  const clone = adjudicate([{ x: 'a' }, { x: 'a' }, { x: 'a' }], ['same', 'same', 'same']);
  assert.equal(clone.independent, false);
  assert.equal(clone.verdict, 'REFUSED');

  // refusals
  assert.equal(adjudicate([{ x: 'a' }, { x: 'a' }], ['a', 'b']).ok, false);          // < MIN_PANEL
  assert.equal(adjudicate([{ x: 'a' }, { x: 'a' }, { x: 'a' }], ['a', 'b']).ok, false); // fp count mismatch
  assert.equal(adjudicate('nope', FPS).ok, false);
  assert.equal(adjudicate([{ x: 'a' }, 'b', { x: 'c' }], FPS).ok, false);             // non-object answer
});

const H = (s) => sha256(s).hash;
const NODES = [
  { fingerprint: 'llama3.2:1b#a', receiptHash: H('ra'), answer: { supplier: 'ACME', total: 100 } },
  { fingerprint: 'qwen2.5:0.5b#b', receiptHash: H('rb'), answer: { supplier: 'ACME', total: 100 } },
  { fingerprint: 'gemma2:2b#c', receiptHash: H('rc'), answer: { supplier: 'ACME', total: 100 } },
];

test('crosscheckReceipt: verifiable receipt; refuses clones; catches tamper + fake independence', () => {
  const r = crosscheckReceipt({ taskHash: H('task'), createdAt: '2026-09-17T00:00:00Z', nodes: NODES });
  assert.equal(r.ok, true);
  assert.equal(r.receipt.kind, 'veridia-crosscheck');
  assert.equal(r.receipt.verdict, 'UNANIMOUS');
  assert.equal(r.receipt.panel.length, 3);
  assert.equal(r.receipt.hash.length, 64);
  assert.equal(verifyCrosscheckReceipt(r.receipt).valid, true);

  // a clone panel cannot even issue a receipt
  const clone = NODES.map((n) => ({ ...n, fingerprint: 'same' }));
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: clone }).ok, false);

  // tamper any signed field → invalid
  assert.equal(verifyCrosscheckReceipt({ ...r.receipt, verdict: 'SPLIT' }).valid, false);

  // forge a receipt whose hash MATCHES its body but whose panel is secretly a clone → the independence
  // invariant catches it even though the hash is consistent
  const body = { ...r.receipt }; delete body.hash; delete body.signature;
  body.panel = [body.panel[0], body.panel[0], body.panel[2]];   // duplicate fingerprint
  const forged = { ...body, hash: sha256(canon(body)).hash };
  const v = verifyCrosscheckReceipt(forged);
  assert.equal(v.valid, false);
  assert.ok(v.why.includes('independent'), 'the fake independence is named, got: ' + v.why);

  // signable excludes the signature, includes the self-hash (sign side == verify side)
  const s = crosscheckSignable(r.receipt);
  assert.equal(s.payload.includes('"signature"'), false);
  assert.equal(s.payload.includes(r.receipt.hash), true);
  assert.equal(crosscheckSignable({ ...r.receipt, signature: { alg: 'Ed25519' } }).payload, s.payload);

  // bad inputs — each guard clause isolated
  assert.equal(crosscheckReceipt('nope').ok, false);
  assert.equal(crosscheckReceipt({ taskHash: 7, createdAt: 't', nodes: NODES }).ok, false);              // non-string taskHash
  assert.equal(crosscheckReceipt({ taskHash: 'a'.repeat(63), createdAt: 't', nodes: NODES }).ok, false); // 63 hex (length)
  assert.equal(crosscheckReceipt({ taskHash: 'X'.repeat(64), createdAt: 't', nodes: NODES }).ok, false); // 64 non-hex (HEX)
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: [NODES[0], NODES[1]] }).ok, false); // < MIN_PANEL
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: '', nodes: NODES }).ok, false);       // empty createdAt
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 7, nodes: NODES }).ok, false);        // non-string createdAt
  // a bad SECOND node is named "node 2" (kills the n = i + 1 counter)
  const badSecond = crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: [NODES[0], { ...NODES[1], receiptHash: 'a'.repeat(63) }, NODES[2]] });
  assert.equal(badSecond.ok, false);
  assert.ok(badSecond.why.includes('node 2'), 'the bad second node is named, got: ' + badSecond.why);
  // node receiptHash: 64 non-hex is refused (HEX clause), empty fingerprint is refused
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: [NODES[0], NODES[1], { ...NODES[2], receiptHash: 'X'.repeat(64) }] }).ok, false);
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: [NODES[0], { ...NODES[1], fingerprint: '' }, NODES[2]] }).ok, false);
  assert.equal(crosscheckReceipt({ taskHash: H('task'), createdAt: 't', nodes: [NODES[0], { ...NODES[1], answer: 'x' }, NODES[2]] }).ok, false);
  assert.equal(verifyCrosscheckReceipt({ kind: 'other', hash: 'x' }).ok, false);
  assert.equal(verifyCrosscheckReceipt({ kind: 'veridia-crosscheck' }).ok, false);   // no hash
  assert.equal(crosscheckSignable({ kind: 'veridia-crosscheck' }).ok, false);        // no hash
});

// ── the tetrahedron: compose cross-checks into a verified pipeline ────────────────────────────────
function stepReceipt(seed, answer){
  const nodes = FPS.map((fp, i) => ({ fingerprint: fp, receiptHash: sha256('r' + seed + i).hash, answer }));
  return crosscheckReceipt({ taskHash: sha256('task-' + seed).hash, createdAt: 't', nodes }).receipt;
}
test('composePipeline: binds each step to the prior accepted output; composite verdict; refuses a broken seam', () => {
  const r1 = stepReceipt('extract', { supplier: 'ACME', total: 100 });
  const r2 = stepReceipt('classify', { vat: 'standard', rate: 20 });
  const seam = sha256(canon(r1.accepted)).hash;   // what step 2 must have consumed
  const good = composePipeline([
    { name: 'extract', receipt: r1, inputHash: null },
    { name: 'classify', receipt: r2, inputHash: seam },
  ], '2026-09-18T00:00:00Z');
  assert.equal(good.ok, true);
  assert.equal(good.receipt.kind, 'veridia-pipeline');
  assert.equal(good.receipt.verdict, 'CLEAN');       // both steps unanimous
  assert.equal(good.receipt.steps.length, 2);
  assert.equal(good.receipt.hash.length, 64);
  assert.equal(verifyPipelineReceipt(good.receipt).valid, true);

  // a broken seam (wrong inputHash) is refused — you cannot swap step 2's input
  const broken = composePipeline([{ name: 'extract', receipt: r1, inputHash: null }, { name: 'classify', receipt: r2, inputHash: sha256('wrong').hash }], 't');
  assert.equal(broken.ok, false);
  assert.ok(broken.why.includes('seam'), 'the broken seam is named, got: ' + broken.why);
  assert.ok(broken.why.includes('consume step 1'), 'the seam names the right predecessor step 1 (kills n-1 -> n+1), got: ' + broken.why);
  // the first step must NOT declare an input
  assert.equal(composePipeline([{ name: 'extract', receipt: r1, inputHash: 'x' }, { name: 'classify', receipt: r2, inputHash: seam }], 't').ok, false);

  // FLAGGED: a step whose panel SPLIT → pipeline still issues a receipt, marked FLAGGED
  const rSplit = crosscheckReceipt({ taskHash: sha256('t2').hash, createdAt: 't', nodes: [
    { fingerprint: 'm1#a', receiptHash: sha256('a').hash, answer: { cat: 'x' } },
    { fingerprint: 'm2#b', receiptHash: sha256('b').hash, answer: { cat: 'y' } },
    { fingerprint: 'm3#c', receiptHash: sha256('c').hash, answer: { cat: 'z' } },
  ] }).receipt;
  assert.equal(rSplit.verdict, 'SPLIT');
  const flagged = composePipeline([{ name: 'extract', receipt: r1, inputHash: null }, { name: 'classify', receipt: rSplit, inputHash: seam }], 't');
  assert.equal(flagged.ok, true);
  assert.equal(flagged.receipt.verdict, 'FLAGGED');
  assert.equal(verifyPipelineReceipt(flagged.receipt).valid, true);

  // MAJORITY: a step that reached only a majority (no split) → pipeline MAJORITY
  const rMaj = crosscheckReceipt({ taskHash: sha256('t3').hash, createdAt: 't', nodes: [
    { fingerprint: 'm1#a', receiptHash: sha256('a').hash, answer: { k: 'v' } },
    { fingerprint: 'm2#b', receiptHash: sha256('b').hash, answer: { k: 'v' } },
    { fingerprint: 'm3#c', receiptHash: sha256('c').hash, answer: { k: 'w' } },
  ] }).receipt;
  assert.equal(rMaj.verdict, 'MAJORITY');
  const maj = composePipeline([{ name: 'a', receipt: r1, inputHash: null }, { name: 'b', receipt: rMaj, inputHash: seam }], 't');
  assert.equal(maj.receipt.verdict, 'MAJORITY');

  // refusals
  assert.equal(composePipeline('nope', 't').ok, false);
  assert.equal(composePipeline([{ name: 'x', receipt: r1, inputHash: null }], 't').ok, false);       // < MIN_STEPS
  const badStep2 = composePipeline([{ name: 'x', receipt: r1, inputHash: null }, { name: 'y', receipt: { kind: 'other' }, inputHash: seam }], 't'); // invalid step 2 receipt
  assert.equal(badStep2.ok, false);
  assert.ok(badStep2.why.includes('step 2'), 'the bad second step is named step 2 (kills i+1 -> i-1), got: ' + badStep2.why);
  assert.equal(composePipeline([{ name: '', receipt: r1, inputHash: null }, { name: 'y', receipt: r2, inputHash: seam }], 't').ok, false);   // empty name
  assert.equal(composePipeline([{ name: 'x', receipt: r1, inputHash: null }, { name: 'y', receipt: r2, inputHash: seam }], '').ok, false);   // empty createdAt
  assert.equal(MIN_STEPS, 2);
});

test('verifyPipelineReceipt: catches tamper and a lying composite verdict', () => {
  const r1 = stepReceipt('e', { a: 1 }); const r2 = stepReceipt('c', { b: 2 });
  const p = composePipeline([{ name: 'e', receipt: r1, inputHash: null }, { name: 'c', receipt: r2, inputHash: sha256(canon(r1.accepted)).hash }], 't').receipt;
  assert.equal(verifyPipelineReceipt(p).valid, true);
  assert.equal(verifyPipelineReceipt({ ...p, createdAt: 'x' }).valid, false);   // tamper → hash mismatch
  // forge: claim CLEAN while a step is secretly SPLIT, with a matching hash → the invariant catches it
  const body = { ...p }; delete body.hash; delete body.signature;
  body.steps = body.steps.map((s, i) => (i === 0 ? { ...s, verdict: 'SPLIT' } : s));   // verdict stays CLEAN, a step is SPLIT
  const forged = { ...body, hash: sha256(canon(body)).hash };
  const v = verifyPipelineReceipt(forged);
  assert.equal(v.valid, false);
  assert.ok(v.why.includes('verdict'), 'the lie is named, got: ' + v.why);
  const s = pipelineSignable(p);
  assert.equal(s.payload.includes('"signature"'), false);
  assert.equal(s.payload.includes(p.hash), true);
  assert.equal(verifyPipelineReceipt({ kind: 'other', hash: 'x' }).ok, false);
  assert.equal(pipelineSignable({ kind: 'veridia-pipeline' }).ok, false);   // no hash
  // the split steps guard: non-array steps and a one-step "pipeline" are both invalid (kills the split guard)
  const pbody = { ...p }; delete pbody.hash; delete pbody.signature;
  const noSteps = { ...pbody, steps: 'nope' }; noSteps.hash = sha256(canon(noSteps)).hash;
  assert.equal(verifyPipelineReceipt(noSteps).valid, false);
  const oneStep = { ...pbody, steps: [pbody.steps[0]] }; oneStep.hash = sha256(canon(oneStep)).hash;
  assert.equal(verifyPipelineReceipt(oneStep).valid, false);
});

// ── the cube: aggregate independent verified units into a Merkle department ───────────────────────
test('merkleRoot: deterministic tree, order-fixed, refuses empty/bad leaves', () => {
  const a = sha256('a').hash, b = sha256('b').hash, c = sha256('c').hash;
  assert.equal(merkleRoot([a]).root, a);                     // one leaf hashes to itself
  assert.equal(merkleRoot([a, b]).root, sha256(a + b).hash); // a pair is the hash of its halves
  assert.notEqual(merkleRoot([a, b]).root, merkleRoot([b, a]).root); // leaf order is significant
  // three leaves: the odd node is duplicated up (a || b) then (c || c)
  const expect3 = sha256(sha256(a + b).hash + sha256(c + c).hash).hash;
  assert.equal(merkleRoot([a, b, c]).root, expect3);
  assert.equal(merkleRoot([]).ok, false);
  assert.equal(merkleRoot('nope').ok, false);
  // a bad SECOND leaf is named "leaf 2" (kills the i + 1 counter)
  const emptyLeaf = merkleRoot([a, '']);
  assert.equal(emptyLeaf.ok, false);
  assert.ok(emptyLeaf.why.includes('leaf 2'), 'the empty leaf is named, got: ' + emptyLeaf.why);
  const badLeaf = merkleRoot([a, 7]);
  assert.equal(badLeaf.ok, false);
  assert.ok(badLeaf.why.includes('leaf 2'), 'the non-string leaf is named, got: ' + badLeaf.why);
});

// build a CLEAN pipeline unit (two unanimous steps), a FLAGGED one (a split step), a MAJORITY one
function pipeUnit(sA, aA, sB, aB) {
  const r1 = stepReceipt(sA, aA);
  const r2 = stepReceipt(sB, aB);
  const seam = sha256(canon(r1.accepted)).hash;
  return composePipeline([{ name: 's1', receipt: r1, inputHash: null }, { name: 's2', receipt: r2, inputHash: seam }], 't').receipt;
}
function flaggedPipeUnit() {
  const r1 = stepReceipt('fa', { x: 1 });
  const rSplit = crosscheckReceipt({ taskHash: sha256('fsplit').hash, createdAt: 't', nodes: [
    { fingerprint: 'm1#a', receiptHash: sha256('fa1').hash, answer: { c: 'x' } },
    { fingerprint: 'm2#b', receiptHash: sha256('fa2').hash, answer: { c: 'y' } },
    { fingerprint: 'm3#c', receiptHash: sha256('fa3').hash, answer: { c: 'z' } },
  ] }).receipt;
  const seam = sha256(canon(r1.accepted)).hash;
  return composePipeline([{ name: 's1', receipt: r1, inputHash: null }, { name: 's2', receipt: rSplit, inputHash: seam }], 't').receipt;
}
function majPipeUnit() {
  const r1 = stepReceipt('ma', { x: 1 });
  const rMaj = crosscheckReceipt({ taskHash: sha256('mmaj').hash, createdAt: 't', nodes: [
    { fingerprint: 'm1#a', receiptHash: sha256('ma1').hash, answer: { k: 'v' } },
    { fingerprint: 'm2#b', receiptHash: sha256('ma2').hash, answer: { k: 'v' } },
    { fingerprint: 'm3#c', receiptHash: sha256('ma3').hash, answer: { k: 'w' } },
  ] }).receipt;
  const seam = sha256(canon(r1.accepted)).hash;
  return composePipeline([{ name: 's1', receipt: r1, inputHash: null }, { name: 's2', receipt: rMaj, inputHash: seam }], 't').receipt;
}

test('composeDepartment: rolls verified units into a Merkle department; declares its charter', () => {
  const u1 = pipeUnit('a1', { x: 1 }, 'a2', { y: 2 });   // CLEAN pipeline unit
  const u2 = stepReceipt('cc', { z: 3 });                // UNANIMOUS cross-check unit
  const good = composeDepartment({
    name: 'invoices',
    expected: ['extract', 'audit'],
    units: [{ name: 'extract', receipt: u1 }, { name: 'audit', receipt: u2 }],
    createdAt: '2026-09-18T00:00:00Z',
  });
  assert.equal(good.ok, true);
  assert.equal(good.receipt.kind, 'veridia-department');
  assert.equal(good.receipt.verdict, 'CLEAN');            // both units agreed, charter met
  assert.equal(good.receipt.units.length, 2);
  assert.deepEqual(good.receipt.missing, []);
  assert.deepEqual(good.receipt.unexpected, []);
  assert.equal(good.receipt.merkleRoot.length, 64);
  assert.equal(good.receipt.hash.length, 64);
  assert.equal(verifyDepartmentReceipt(good.receipt).valid, true);

  // the department id is order-independent: the SAME units in the other order → the SAME Merkle root
  const swapped = composeDepartment({ name: 'invoices', expected: ['extract', 'audit'], units: [{ name: 'audit', receipt: u2 }, { name: 'extract', receipt: u1 }], createdAt: '2026-09-18T00:00:00Z' });
  assert.equal(swapped.receipt.merkleRoot, good.receipt.merkleRoot);

  // Kar's honest rule — a MISSING unit makes the department INCOMPLETE and is NAMED (a dropped process can't hide)
  const incomplete = composeDepartment({ name: 'invoices', expected: ['extract', 'audit'], units: [{ name: 'extract', receipt: u1 }], createdAt: 't' });
  assert.equal(incomplete.ok, true);
  assert.equal(incomplete.receipt.verdict, 'INCOMPLETE');
  assert.deepEqual(incomplete.receipt.missing, ['audit']);
  assert.equal(verifyDepartmentReceipt(incomplete.receipt).valid, true);

  // an UNINVITED unit (present but not in the charter) is also INCOMPLETE and named
  const extra = composeDepartment({ name: 'invoices', expected: ['extract', 'audit'], units: [{ name: 'extract', receipt: u1 }, { name: 'audit', receipt: u2 }, { name: 'ghost', receipt: u2 }], createdAt: 't' });
  assert.equal(extra.receipt.verdict, 'INCOMPLETE');
  assert.deepEqual(extra.receipt.unexpected, ['ghost']);

  // a ZERO-unit department (nothing supplied) still issues an honest INCOMPLETE receipt — both units named
  // missing, no Merkle root — rather than refusing (the guard `leaves.length > 0` must stay strict)
  const empty = composeDepartment({ name: 'invoices', expected: ['extract', 'audit'], units: [], createdAt: 't' });
  assert.equal(empty.ok, true);
  assert.equal(empty.receipt.verdict, 'INCOMPLETE');
  assert.deepEqual(empty.receipt.missing, ['extract', 'audit']);
  assert.equal(empty.receipt.merkleRoot, null);
  assert.equal(verifyDepartmentReceipt(empty.receipt).valid, true);

  // a FLAGGED unit (charter met) → the whole department is FLAGGED
  const flagged = composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: u1 }, { name: 'b', receipt: flaggedPipeUnit() }], createdAt: 't' });
  assert.equal(flagged.receipt.verdict, 'FLAGGED');
  assert.equal(verifyDepartmentReceipt(flagged.receipt).valid, true);

  // a MAJORITY unit (charter met, none flagged) → the department is MAJORITY
  const majd = composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: u1 }, { name: 'b', receipt: majPipeUnit() }], createdAt: 't' });
  assert.equal(majd.receipt.verdict, 'MAJORITY');

  // refusals — each guard isolated
  assert.equal(composeDepartment('nope').ok, false);
  assert.equal(composeDepartment({ name: '', expected: ['a', 'b'], units: [], createdAt: 't' }).ok, false);        // empty name
  assert.equal(composeDepartment({ name: 'd', expected: ['a'], units: [], createdAt: 't' }).ok, false);           // < MIN_UNITS charter
  assert.equal(composeDepartment({ name: 'd', expected: ['a', 'a'], units: [], createdAt: 't' }).ok, false);      // non-distinct charter
  // a bad SECOND charter entry is named "expected unit 2" (kills the i + 1 counter on lines 382/383)
  const badExpName = composeDepartment({ name: 'd', expected: ['ok', 7], units: [], createdAt: 't' });
  assert.equal(badExpName.ok, false);
  assert.ok(badExpName.why.includes('expected unit 2'), 'the bad charter entry is named, got: ' + badExpName.why);
  const emptyExpName = composeDepartment({ name: 'd', expected: ['ok', '  '], units: [], createdAt: 't' });
  assert.equal(emptyExpName.ok, false);
  assert.ok(emptyExpName.why.includes('expected unit 2'), 'the empty charter entry is named, got: ' + emptyExpName.why);
  assert.equal(composeDepartment({ name: 'd', expected: ['a', 'b'], units: [], createdAt: '' }).ok, false);       // empty createdAt
  assert.equal(composeDepartment({ name: 'd', expected: ['a', 'b'], units: 'nope', createdAt: 't' }).ok, false);  // units not a list
  // a bad SECOND unit is named "unit 2" (kills the n = i + 1 counter)
  const badSecond = composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: u1 }, { name: 'b', receipt: { kind: 'other' } }], createdAt: 't' });
  assert.equal(badSecond.ok, false);
  assert.ok(badSecond.why.includes('unit 2'), 'the bad second unit is named, got: ' + badSecond.why);
  // a TAMPERED unit receipt is refused — you cannot build a department on a broken unit
  const tampered = { ...u1, verdict: 'MAJORITY' };   // hash no longer matches its body
  assert.equal(composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: tampered }, { name: 'b', receipt: u2 }], createdAt: 't' }).ok, false);
  // duplicate present unit names are refused (two 'a' units would mask one)
  assert.equal(composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: u1 }, { name: 'a', receipt: u2 }], createdAt: 't' }).ok, false);
  assert.equal(MIN_UNITS, 2);
});

test('verifyDepartmentReceipt: catches tamper, a lying verdict, and a forged completeness record', () => {
  const u1 = pipeUnit('a1', { x: 1 }, 'a2', { y: 2 });
  const u2 = stepReceipt('cc', { z: 3 });
  const d = composeDepartment({ name: 'd', expected: ['a', 'b'], units: [{ name: 'a', receipt: u1 }, { name: 'b', receipt: u2 }], createdAt: 't' }).receipt;
  assert.equal(verifyDepartmentReceipt(d).valid, true);
  assert.equal(verifyDepartmentReceipt({ ...d, createdAt: 'x' }).valid, false);   // tamper → hash mismatch

  // forge 1: claim CLEAN while a unit is secretly FLAGGED, re-match the hash → the verdict invariant catches it
  const b1 = { ...d }; delete b1.hash; delete b1.signature;
  b1.units = b1.units.map((u, i) => (i === 0 ? { ...u, verdict: 'FLAGGED' } : u));   // verdict stays CLEAN, a unit is FLAGGED
  const forgedVerdict = { ...b1, hash: sha256(canon(b1)).hash };
  const v1 = verifyDepartmentReceipt(forgedVerdict);
  assert.equal(v1.valid, false);
  assert.ok(v1.why.includes('verdict'), 'the lie is named, got: ' + v1.why);

  // forge 2: drop unit 'b' but keep missing:[] and CLEAN (hide the gap), re-match the hash →
  // the completeness invariant catches it (recomputed against the charter)
  const b2 = { ...d }; delete b2.hash; delete b2.signature;
  b2.units = [b2.units[0]];   // only 'a' remains, but expected is still ['a','b']
  b2.missing = [];            // the lie: claims nothing is missing
  b2.verdict = 'CLEAN';
  const forgedComplete = { ...b2, hash: sha256(canon(b2)).hash };
  const v2 = verifyDepartmentReceipt(forgedComplete);
  assert.equal(v2.valid, false);
  assert.ok(v2.why.includes('charter') || v2.why.includes('completeness'), 'the hidden gap is named, got: ' + v2.why);

  const s = departmentSignable(d);
  assert.equal(s.payload.includes('"signature"'), false);
  assert.equal(s.payload.includes(d.hash), true);
  assert.equal(departmentSignable({ ...d, signature: { alg: 'Ed25519' } }).payload, s.payload);
  assert.equal(verifyDepartmentReceipt({ kind: 'other', hash: 'x' }).ok, false);
  assert.equal(verifyDepartmentReceipt({ kind: 'veridia-department' }).ok, false);   // no hash
  assert.equal(departmentSignable({ kind: 'veridia-department' }).ok, false);         // no hash
  // the charter guard on verify: a receipt whose expected shrank below MIN_UNITS is invalid
  const b3 = { ...d }; delete b3.hash; delete b3.signature;
  const shortCharter = { ...b3, expected: ['a'] }; shortCharter.hash = sha256(canon(shortCharter)).hash;
  assert.equal(verifyDepartmentReceipt(shortCharter).valid, false);
});
