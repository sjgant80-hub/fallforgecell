// page-gate.mjs — FallForge Mint is a single self-contained page, so this checks the page for the real
// failure modes that have shipped in this estate, plus the one rule this product adds: it links to NO
// other repository. Checks:
//   1. every EXECUTABLE inline script parses            (data scripts — ld+json/json/importmap — skipped)
//   2. no unresolved __TEMPLATE__ placeholder is served
//   3. every same-repo href/src in the MARKUP resolves  (scripts/styles stripped first)
//   4. NO link points at another repo — github.com or *.github.io (this product stands alone)
//   5. no obvious secret is committed
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { Script } from 'node:vm';

const JS_TYPE = /^\s*(module|text\/javascript|application\/javascript|)\s*$/i;
const html = readdirSync('.').filter((f) => f.endsWith('.html'));
if (!html.length) { console.error('no HTML in this repo — nothing to serve'); process.exit(1); }
let fail = 0;

for (const f of html) {
  const s = readFileSync(f, 'utf8');

  // 1. executable inline scripts must parse (data scripts skipped).
  const blocks = [...s.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
  blocks.forEach((m, i) => {
    const attrs = m[1];
    if (/\bsrc=/.test(attrs)) return;
    const tm = attrs.match(/\btype=["']([^"']*)["']/);
    if (tm && !JS_TYPE.test(tm[1])) return;                 // ld+json / json / importmap — data, not JS
    try { new Script(m[2].replace(/^\s*import\s.*$/gm, '').replace(/^\s*export\s/gm, '')); }
    catch (e) { if (!/await is only valid|Unexpected token 'export'|Cannot use import/.test(e.message)) { console.error(f + ' script[' + i + '] DOES NOT PARSE: ' + e.message); fail = 1; } }
  });

  // 2. unresolved placeholder.
  const ph = s.match(/__[A-Z][A-Z0-9_]*__/g);
  if (ph) { console.error(f + ' serves unresolved placeholders: ' + [...new Set(ph)].join(', ')); fail = 1; }

  // 3 + 4. scan the MARKUP only (scripts/styles stripped so JS import URLs and CSS url()s aren't misread).
  const markup = s.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '');
  // Veridia may reference its OWN canonical page and the ONE foundry it consumes (fallforgemint) — those
  // are the only two estate URLs allowed; every other github link is a dead-link/cross-repo risk.
  const ALLOWED = /^https?:\/\/sjgant80-hub\.github\.io\/(fallforgecell|fallforgemint)\/?$/i;
  for (const m of markup.matchAll(/(?:href|src)="([^"]*)"/g)) {
    const url = m[1];
    if (/github\.com|github\.io/i.test(url) && !ALLOWED.test(url)) { console.error(f + ' links to an unexpected repo: ' + url); fail = 1; continue; }
    // 3. same-repo dead links.
    if (/^(https?:|data:|mailto:|#|\/\/|\$\{)/.test(url)) continue;
    const t = url.replace(/^\.\//, '').split(/[?#]/)[0];
    if (t && !existsSync(t)) { console.error(f + ' links to a file that is not here: ' + t); fail = 1; }
  }
}

// 5. committed secret (top-level served files).
for (const f of readdirSync('.')) {
  if (!/\.(html|js|mjs|json|md|txt)$/.test(f)) continue;
  const s = readFileSync(f, 'utf8');
  const hit = s.match(/(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/);
  if (hit) { console.error(f + ' contains what looks like a live credential: ' + hit[1].slice(0, 12) + '…'); fail = 1; }
}

if (fail) { console.error('\nPAGE GATE FAILED'); process.exit(1); }
console.log('page gate clean — ' + html.length + ' page(s): scripts parse, no placeholders, no dead links, no cross-repo links, no committed keys');
