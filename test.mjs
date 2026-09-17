import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MIN_PANEL,
  sha256, canon, normValue, agree,
  panelIndependent, adjudicateField, adjudicate,
  crosscheckReceipt, crosscheckSignable, verifyCrosscheckReceipt,
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
