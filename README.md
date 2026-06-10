# CiteStamp op-log

Append-only log of signed CiteStamp assertion and retraction events.

Each `assertions-YYYY-MM.jsonl` file holds one canonical-JSON event per
line. Every line carries an RSA signature from the asserter's published
key and a `prev_line_hash` chaining it to the previous line, so the full
history can be verified back to genesis by any reader.

This log is the system of record. Databases serving the CiteStamp API
are materialized views over it and can be rebuilt from this repository
alone.

Log contents are dedicated to the public domain under CC0 1.0.
