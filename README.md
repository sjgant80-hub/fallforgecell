# Veridia (fallforgecell)

**▶ LIVE: https://sjgant80-hub.github.io/fallforgecell/**

Veridia is the **cell** of the FallForge estate — the organ that makes a composition of AI task-nodes not just *safe*, but *correct*.

[fallforgemint](https://github.com/sjgant80-hub/fallforgemint) is the 0D foundry: it mints one owned, proven, signed task-node. Veridia is the next step up — the **triangle**: it takes *three independent* nodes, runs them on the same input, and cross-checks their answers so a confidently-wrong node gets caught. It **consumes** what the foundry produces (outputs + signed scorecards); it never mints models and never touches the foundry.

## Why three, and why *independent*

A single node — even a proven one — can be confidently, plausibly wrong (a mis-read total, a wrong-but-valid supplier) and nothing downstream catches it. A closed loop of three can: two independent nodes cross-check the third.

The load-bearing rule, and the honest one: **agreement among identical nodes is not verification.** Three clones tell the same confident lie three times. So Veridia **refuses a panel whose members aren't distinct models**, and the receipt records the three fingerprints as proof the cross-check was real. A triangle of clones is theatre, and Veridia says so.

## What it does (per field, honestly)

Three independent nodes answer the same task. Veridia adjudicates **each field**:

- **UNANIMOUS** — all three agree (after normalising formatting: `0` = `0.00`, `2023-01-15` = `2023-01-15T00:00:00Z`).
- **MAJORITY** — two agree; the answer is accepted and the dissenter is recorded (never hidden).
- **SPLIT** — no majority; *that field* escalates to a human or a frontier model. Accepted fields still stand.

It emits a signed cross-check receipt binding the panel (independence proof), the node receipt hashes (the chain back to each scorecard), the per-field verdicts, and what escalated — re-verifiable offline.

**Honest scope:** the cross-check proves the panel *agreed and was independent*, **not that they were right** — a unanimous panel can be unanimously wrong. SPLIT is where a human belongs. Veridia draws that line; it does not pretend to erase it.

## The gate (CI, every push)

- `node --test test.mjs` — the contract suite.
- `node tools/witness.mjs mutate kernel.mjs` — the mutation gate must be **CLEAN**.
- `node make-page.mjs && git diff --exit-code index.html` — the live page IS the gated kernel.
- `node tools/page-gate.mjs` — scripts parse, no placeholders, no dead links, no committed secrets.

Part of the FallForge estate. Powered by the Konomi architecture, created by Thomas Frumkin. MIT. ◊·κ=1.
