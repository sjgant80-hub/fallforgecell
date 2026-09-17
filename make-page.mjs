#!/usr/bin/env node
// make-page.mjs — the page fixpoint. index.html runs the SAME kernel the witness gates, by inlining
// kernel.mjs between the two markers below. CI runs this and then `git diff --exit-code index.html`:
// if the shipped page's logic ever drifts from the gated kernel, the build goes red. One kernel, gated
// once, is the live logic — no second hand-typed copy to rot.
import { readFileSync, writeFileSync } from 'node:fs';
const kernel = readFileSync(new URL('./kernel.mjs', import.meta.url), 'utf8')
  .replace(/^export /gm, '').replace(/\r\n/g, '\n').trimEnd();
const page = readFileSync(new URL('./index.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const BEGIN = '// ⟦KERNEL-BEGIN⟧ generated from kernel.mjs by make-page.mjs — do not edit here';
const END = '// ⟦KERNEL-END⟧';
const a = page.indexOf(BEGIN), b = page.indexOf(END);
if (a === -1 || b === -1 || b < a) { console.error('markers missing in index.html'); process.exit(1); }
writeFileSync(new URL('./index.html', import.meta.url), page.slice(0, a + BEGIN.length) + '\n' + kernel + '\n' + page.slice(b));
console.log('kernel injected: ' + kernel.length + ' chars');
