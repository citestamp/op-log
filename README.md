# CiteStamp op-log

Append-only log of signed CiteStamp assertion and retraction events.

The genesis file `assertions.jsonl` holds the seed events; every event
appended thereafter lands in a monthly `assertions-YYYY-MM.jsonl` file.
To verify by hand, read `assertions.jsonl` first, then the monthly files
in ascending order. Each file holds one canonical-JSON event per line.
Every line carries an RSA signature from the asserter's published key and
a `prev_line_hash` chaining it to the previous line, so the full history
can be verified back to genesis by any reader.

## What this log is the system of record for

The signed layer, completely. Every asserted edge, every retraction, and
every asserter enrollment the CiteStamp API serves is replayed from these
files, and that layer can be rebuilt from this repository alone.

Two things are deliberately not here.

**Machine-inferred edges.** They are derived from public scholarly
metadata, they are labelled `inferred` everywhere they appear, and they
are reproducible from those sources rather than from this log. Nothing in
this repository is machine-guessed.

**Identifier aliasing** — the mapping that lets two identifiers for the
same work resolve to one node. It is not recorded here yet. Until it is,
a rebuild from this repository resolves every identifier to itself. That
gap is ours; it is stated here rather than discovered later.

Log contents are dedicated to the public domain under CC0 1.0.
