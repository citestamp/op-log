# CiteStamp op-log

Append-only log of signed CiteStamp events: assertions, retractions, and
identifier merges.

The genesis file `assertions.jsonl` holds the seed events; every event
appended thereafter lands in a monthly `assertions-YYYY-MM.jsonl` file.
Each file holds one canonical-JSON event per line. Every line carries an RSA
signature made with the asserter's key published in `asserters.json`, and a
`prev_line_hash` chaining it to the previous line. To check the log by hand,
take the keys from `asserters.json`, then read `assertions.jsonl` and the
monthly files in ascending order; the chain and every signature on it can be
checked back to genesis by any reader.

## What this log is the system of record for

The signed layer, completely. Every asserted edge, every retraction, and every
identifier merge the CiteStamp API serves is a signed line in these files.
Together with the asserter registry in `asserters.json` — the trust root, which
is published rather than signed, because a root cannot sign itself — that layer
can be rebuilt from this repository alone.

**Identifier merges** are how two identifiers for the same work — a DOI, a
Wikidata item, an internal slug — come to resolve to one node. Each is a signed
`merge` event naming a `child` and the `parent` it collapses into. To resolve
any identifier, follow `child` to `parent` until no merge names it as a child;
that node is canonical. Merges chain, so a Wikidata item may reach its DOI
through an intermediate node, and an identifier no merge mentions resolves to
itself. A rebuild from this repository therefore resolves every identifier the
way the live API does.

A merge is signed, chained, and readable back like every other line here.
Unlike an assertion, it cannot be retracted — there is no un-merge event —
which is why only a sovereign asserter may issue one.

Two things are not in this log.

**Machine-inferred edges**, deliberately. They are derived from public scholarly
metadata, they are labelled `inferred` everywhere they appear, and they are
reproducible from those sources rather than from this log. Nothing in this
repository is machine-guessed.

**The text of a claim node.** An edge may name `claim:...` as its subject or
object; the short statement that claim node displays is not a signed event and
is not recorded here. A rebuild restores every edge that points at a claim, but
not the sentence the claim reads as. That gap is ours; it is stated here rather
than discovered later.

Log contents are dedicated to the public domain under CC0 1.0.
