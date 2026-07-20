# CiteStamp op-log

Append-only log of signed CiteStamp events: assertions, retractions,
identifier merges, asserter enrollments, and asserter revocations.

The genesis file `assertions.jsonl` holds the seed events; every event
appended thereafter lands in a monthly `assertions-YYYY-MM.jsonl` file.
Each file holds one canonical-JSON event per line. Every line carries an RSA
signature made with the asserter's key published in `asserters.json`, and a
`prev_line_hash` chaining it to the previous line. To check the log by hand,
take the keys from `asserters.json`, then read `assertions.jsonl` and the
monthly files in ascending order; the chain and every signature on it can be
checked back to genesis by any reader.

## Verifying this log

```
node verify_oplog.mjs .
```

`verify_oplog.mjs` (in this repo; Node ≥ 18, no dependencies) checks every
line: the canonical-JSON RSA signature, `prev_line_hash` chain continuity
across the genesis file and the monthly files, that every non-genesis signer
entered through a sovereign-signed enrollment, and the chain-order
revocation and rotation rules below. Exit code 0 means every line in the log
is valid. You do not need to trust CiteStamp to run it — the keys, the
lines, and the verifier are all in front of you.

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

## Log format v1.1 — revocation and key rotation

Format v1.1 adds one line type, `revoke_asserter`, and fixes the replay
semantics for it.

**Enrollment.** New asserters never edit `asserters.json` — that file stays
the genesis roots only. A new signer enters the trust set through a
sovereign-signed `enroll_asserter` line in the chain. The sovereign's
enrollment signature attests exactly one thing: *an ORCID-authenticated
session for that iD submitted that public key.* It is not an endorsement of
the asserter or of anything they later sign; every subsequent line stands or
falls on the asserter's own signature.

**`revoke_asserter`** ends trust in an asserter's key from that point in the
chain forward:

```json
{"type":"revoke_asserter","asserter_id":"https://orcid.org/...","reason":"...",
 "revoked_by":"ICSAC-00001","created":"...","prev_line_hash":"...","signature":"..."}
```

`revoked_by` must be an existing, unrevoked sovereign; the target must be
enrolled and not already revoked; the target never signs its own
revocation. The `reason` is part of the public record.

**Revocation is chain-ordered and non-retroactive.** A line is valid iff its
asserter was enrolled and not yet revoked *at that point in the chain*,
verified against the public key in effect at that point. Lines appended
before a revocation remain valid forever: they were signed while the key was
trusted, and invalidating them afterwards would relabel history, which an
append-only log must never do. Revocation stops future lines; it removes and
reinterprets nothing. The only way a signed line is ever withdrawn is a
signed, public `retract` line — itself part of this log.

**Key rotation** is a revocation plus a re-enrollment: `revoke_asserter` for
the old key, then a fresh `enroll_asserter` for the *same* `asserter_id`
with the new public key. Replay applies both in chain order — the old key
verifies the lines that came before its revocation, the new key verifies the
lines that come after the re-enrollment, and an old-key line appended after
the rotation fails. Re-enrolling an asserter that is not revoked is invalid:
a live identity cannot be silently re-keyed.

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
