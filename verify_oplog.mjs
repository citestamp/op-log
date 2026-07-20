#!/usr/bin/env node
/**
 * verify_oplog.mjs — public, dependency-free verifier for the CiteStamp op-log.
 *
 * Anyone can check this log without trusting CiteStamp: clone the repo, run
 *
 *     node verify_oplog.mjs .
 *
 * (Node >= 18, no npm packages). Exit code 0 means every line in the log is
 * valid; anything else means at least one line failed and the failures were
 * printed. Add --json for a machine-readable summary on stdout.
 *
 * What is verified, per line, in chain order across `assertions.jsonl`
 * (genesis) then `assertions-YYYY-MM.jsonl` ascending:
 *
 *   1. CHAIN — `prev_line_hash` equals the SHA-256 hex of the canonical JSON
 *      of the previous valid line minus its `signature` ("" for the first
 *      line). The signature covers `prev_line_hash`, so a signer commits to
 *      what their line follows; reordering breaks signatures, not just hashes.
 *   2. SIGNATURE — base64 RSA-PKCS1-v1_5 / SHA-256 over the canonical JSON of
 *      the line minus `signature` (sorted keys, no whitespace, UTF-8),
 *      verified against the signer's public key IN EFFECT AT THAT POINT in
 *      the chain.
 *   3. MEMBERSHIP — the signer must be in the working asserter set: the
 *      genesis roots in `asserters.json` (published, not signed — a trust
 *      root cannot sign itself) plus every verified `enroll_asserter` line so
 *      far, minus chain-ordered revocations. `enroll_asserter` and
 *      `revoke_asserter` lines must be signed by an unrevoked SOVEREIGN
 *      (their `enrolled_by` / `revoked_by` field), never by the asserter they
 *      name.
 *   4. REVOCATION (log format v1.1) — chain-ordered and NON-retroactive: a
 *      `revoke_asserter` line stops its target's key from verifying lines
 *      AFTER it; every line the target signed before it remains valid
 *      forever. Revoking an unknown or already-revoked asserter is invalid.
 *   5. ROTATION (log format v1.1) — re-enrolling a REVOKED asserter_id with a
 *      new public key re-keys the identity: the new key verifies subsequent
 *      lines, the old key does not. Enrolling an id that is present and NOT
 *      revoked is invalid (it would silently re-key a live identity).
 *
 * An invalid line is reported and skipped; it does not advance the chain, so
 * later lines that chain onto the last VALID line still verify. This mirrors
 * exactly what CiteStamp's own recovery replay accepts
 * (cloud/scripts/reconstruct_oplog.py in the citestamp code repo) — the two
 * implementations are cross-checked against shared fixtures.
 */

import { readFileSync, readdirSync } from "node:fs"
import { join } from "node:path"
import { webcrypto, createHash } from "node:crypto"

const { subtle } = webcrypto

// ---------- canonical JSON (mirror of the signer's serialization) ----------

const JS_SAFE_INT_MAX = Number.MAX_SAFE_INTEGER

// Sort keys by Unicode code point (Python's sort_keys=True). JS default sort
// is by UTF-16 code unit, which orders astral-plane keys before high-BMP keys
// — the opposite of Python. Compare by code point to match.
function compareCodePoints(a, b) {
  const aa = [...a]
  const bb = [...b]
  const n = Math.min(aa.length, bb.length)
  for (let i = 0; i < n; i++) {
    const ca = aa[i].codePointAt(0)
    const cb = bb[i].codePointAt(0)
    if (ca !== cb) return ca - cb
  }
  return aa.length - bb.length
}

function canonicalJSON(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]"
  const keys = Object.keys(value).sort(compareCodePoints)
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(value[k])).join(",") + "}"
}

function canonicalBytes(value) {
  return new TextEncoder().encode(canonicalJSON(value))
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex")
}

// Reject scalars that serialize differently across runtimes (floats, ints
// outside the JS safe range, unpaired surrogates, C0 controls other than
// TAB/LF/CR — in values and keys). Signed lines never carry them.
function assertCanonicalSafe(v, path = "$") {
  if (v === null) return
  const t = typeof v
  if (t === "boolean") return
  if (t === "string") {
    for (let i = 0; i < v.length; i++) {
      const code = v.charCodeAt(i)
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = i + 1 < v.length ? v.charCodeAt(i + 1) : -1
        if (next < 0xdc00 || next > 0xdfff) throw new Error(`unpaired high surrogate at ${path}[${i}]`)
        i++
        continue
      }
      if (code >= 0xdc00 && code <= 0xdfff) throw new Error(`unpaired low surrogate at ${path}[${i}]`)
      if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) {
        throw new Error(`disallowed control codepoint at ${path}[${i}]`)
      }
    }
    return
  }
  if (t === "number") {
    if (!Number.isFinite(v)) throw new Error(`non-finite number at ${path}`)
    if (!Number.isInteger(v)) throw new Error(`float scalar at ${path}: ${v}`)
    if (v > JS_SAFE_INT_MAX || v < -JS_SAFE_INT_MAX) throw new Error(`int outside JS safe range at ${path}`)
    return
  }
  if (Array.isArray(v)) {
    v.forEach((item, i) => assertCanonicalSafe(item, `${path}[${i}]`))
    return
  }
  if (t === "object") {
    for (const [k, vv] of Object.entries(v)) {
      assertCanonicalSafe(k, `${path}.<key>`)
      assertCanonicalSafe(vv, `${path}.${k}`)
    }
    return
  }
  throw new Error(`unsupported scalar type ${t} at ${path}`)
}

// ---------- line shapes ----------

const REQUIRED_FIELDS = {
  assert: ["edge_id", "subject", "predicate", "object", "asserter", "provenance", "license", "created"],
  retract: ["retraction_id", "target_edge_id", "asserter", "created"],
  merge: ["child", "parent", "tier", "asserter", "created"],
  enroll_asserter: ["asserter_id", "public_key", "tier", "issued"],
  revoke_asserter: ["asserter_id", "reason", "revoked_by", "created"],
}
const STRING_FIELDS = {
  assert: ["edge_id", "subject", "predicate", "object", "asserter", "license", "created"],
  retract: ["retraction_id", "target_edge_id", "asserter", "created"],
  merge: ["child", "parent", "tier", "asserter", "created"],
  enroll_asserter: ["asserter_id", "public_key", "tier", "issued"],
  revoke_asserter: ["asserter_id", "reason", "revoked_by", "created"],
}
const OPTIONAL_STRING_FIELDS = {
  assert: ["np_uri", "legacy_nanopub_sig_sha256"],
  retract: ["target_np_uri", "np_uri", "reason"],
  merge: [],
  enroll_asserter: ["orcid_id"],
  revoke_asserter: [],
}
const MERGE_TIERS = ["asserted", "inferred"]
// Sovereign tier is genesis-only (asserters.json); an enroll line granting it
// would be a privilege escalation and fails the shape gate.
const ENROLL_TIERS = ["federated", "observed"]

function checkLineShape(parsed) {
  const t = parsed.type
  if (!(t in REQUIRED_FIELDS)) return `unknown op-log line type: ${JSON.stringify(t)}`
  for (const f of REQUIRED_FIELDS[t]) {
    if (!(f in parsed)) return `${t} line missing field: ${f}`
  }
  for (const f of STRING_FIELDS[t]) {
    if (typeof parsed[f] !== "string") return `${t} line field '${f}' must be a string`
  }
  for (const f of OPTIONAL_STRING_FIELDS[t]) {
    const v = parsed[f]
    if (v !== undefined && v !== null && typeof v !== "string") {
      return `${t} line field '${f}' must be a string or null`
    }
  }
  if (t === "assert" && (typeof parsed.provenance !== "object" || parsed.provenance === null)) {
    return "assert line field 'provenance' must be an object or array"
  }
  if (t === "merge") {
    if (!MERGE_TIERS.includes(parsed.tier)) return `merge tier must be one of ${MERGE_TIERS.join("/")}`
    if (parsed.child === parsed.parent) return "merge child and parent are the same identifier"
  }
  if (t === "enroll_asserter" && !ENROLL_TIERS.includes(parsed.tier)) {
    return `enroll_asserter tier must be one of ${ENROLL_TIERS.join("/")}`
  }
  return null
}

// ---------- signature verification ----------

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, "base64"))
}

const keyCache = new Map() // spkiB64 -> CryptoKey | null
async function importPubKey(spkiB64) {
  if (keyCache.has(spkiB64)) return keyCache.get(spkiB64)
  let key = null
  try {
    key = await subtle.importKey(
      "spki",
      b64ToBytes(spkiB64),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    )
  } catch {
    key = null
  }
  keyCache.set(spkiB64, key)
  return key
}

async function verifySignature(rest, sigB64, spkiB64) {
  const key = await importPubKey(spkiB64)
  if (!key) return false
  let sigBytes
  try {
    sigBytes = b64ToBytes(sigB64)
  } catch {
    return false
  }
  return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sigBytes, canonicalBytes(rest))
}

// ---------- file discovery (genesis first, then months ascending) ----------

function sortKeyForPath(name) {
  if (name === "assertions.jsonl") return ""
  return name.slice("assertions-".length, -".jsonl".length) // YYYY-MM
}

function discoverLogFiles(dir) {
  const names = readdirSync(dir).filter(
    (n) => n.startsWith("assertions") && n.endsWith(".jsonl"),
  )
  names.sort((a, b) => (sortKeyForPath(a) < sortKeyForPath(b) ? -1 : sortKeyForPath(a) > sortKeyForPath(b) ? 1 : 0))
  return names
}

// ---------- replay ----------

async function main() {
  const args = process.argv.slice(2)
  const json = args.includes("--json")
  const dir = args.find((a) => !a.startsWith("--")) ?? "."

  // Genesis trust roots. asserters.json is published rather than signed —
  // a root cannot sign itself — and holds sovereigns only; every other
  // signer enters via a chained, sovereign-signed enroll_asserter line.
  const asserters = new Map()
  for (const row of JSON.parse(readFileSync(join(dir, "asserters.json"), "utf8"))) {
    asserters.set(row.asserter_id, {
      public_key: row.public_key,
      tier: row.tier,
      revoked: row.revoked ?? null,
    })
  }

  const files = discoverLogFiles(dir)
  if (files.length === 0) {
    console.error(`no assertions*.jsonl files found in ${dir}`)
    process.exit(2)
  }

  let prevHash = ""
  let applied = 0
  let skipped = 0
  let lastLine = -1
  const skips = [] // {file, line, reason}

  const skip = (file, fileLine, reason, detail) => {
    skipped++
    skips.push({ file, line: fileLine, reason })
    console.log(`SKIP ${file}:${fileLine}: ${detail ?? reason}`)
  }

  for (const file of files) {
    console.log(`# file: ${file}`)
    const content = readFileSync(join(dir, file), "utf8")
    let fileLine = 0
    for (const raw of content.split("\n")) {
      if (!raw.trim()) continue
      fileLine++

      let parsed
      try {
        parsed = JSON.parse(raw)
      } catch {
        skip(file, fileLine, "invalid JSON")
        continue
      }

      // 1. CHAIN — must equal the hash of the last VALID line.
      const declaredPrev = parsed.prev_line_hash ?? ""
      if (declaredPrev !== prevHash) {
        skip(
          file,
          fileLine,
          "chain break",
          `chain break: expected prev_line_hash=${JSON.stringify(prevHash)}, got ${JSON.stringify(declaredPrev)}`,
        )
        continue
      }

      const { signature, ...rest } = parsed
      if (typeof signature !== "string") {
        skip(file, fileLine, "missing signature")
        continue
      }

      try {
        assertCanonicalSafe(rest)
      } catch (e) {
        skip(file, fileLine, "canonical-safety", `canonical-safety: ${e.message}`)
        continue
      }

      const shapeErr = checkLineShape(rest)
      if (shapeErr !== null) {
        skip(file, fileLine, "shape", shapeErr)
        continue
      }

      // 3. MEMBERSHIP — resolve the signer: enroll/revoke lines are signed by
      // their sovereign sponsor, everything else by its `asserter`.
      const isEnroll = rest.type === "enroll_asserter"
      const isRevoke = rest.type === "revoke_asserter"
      const signerId = isEnroll ? rest.enrolled_by : isRevoke ? rest.revoked_by : rest.asserter
      const signer = typeof signerId === "string" ? asserters.get(signerId) : undefined
      if (!signer) {
        skip(file, fileLine, "unknown signer", `unknown asserter ${JSON.stringify(signerId)}`)
        continue
      }
      if (signer.revoked) {
        // Chain-order: `revoked` here is chain state at this position, so
        // this rejects only lines that landed AFTER the signer's revoke.
        skip(file, fileLine, "signer revoked", `asserter ${signerId} revoked at ${signer.revoked}`)
        continue
      }
      if ((isEnroll || isRevoke) && signer.tier !== "sovereign") {
        skip(file, fileLine, "signer not sovereign", `${rest.type} signed by non-sovereign ${JSON.stringify(signerId)}`)
        continue
      }

      // 2. SIGNATURE — against the key in effect at this chain position.
      if (!(await verifySignature(rest, signature, signer.public_key))) {
        skip(file, fileLine, "signature invalid")
        continue
      }

      // 4./5. Target semantics for enroll/revoke.
      if (isEnroll) {
        const existing = asserters.get(rest.asserter_id)
        if (existing && !existing.revoked) {
          skip(
            file,
            fileLine,
            "enroll of unrevoked asserter",
            `enroll_asserter for already-enrolled, unrevoked ${JSON.stringify(rest.asserter_id)} (rotation requires a prior revoke)`,
          )
          continue
        }
      } else if (isRevoke) {
        const target = asserters.get(rest.asserter_id)
        if (!target) {
          skip(file, fileLine, "revoke of unknown asserter", `revoke_asserter for unknown ${JSON.stringify(rest.asserter_id)}`)
          continue
        }
        if (target.revoked) {
          skip(
            file,
            fileLine,
            "revoke of already-revoked asserter",
            `revoke_asserter for already-revoked ${JSON.stringify(rest.asserter_id)} (revoked at ${target.revoked})`,
          )
          continue
        }
      }

      // Valid — apply membership effects and advance the chain.
      if (isEnroll) {
        asserters.set(rest.asserter_id, {
          public_key: rest.public_key,
          tier: rest.tier,
          revoked: null,
        })
      } else if (isRevoke) {
        asserters.get(rest.asserter_id).revoked = rest.created
      }
      prevHash = sha256Hex(canonicalBytes(rest))
      lastLine++
      applied++
    }
  }

  console.log(`RESULT applied=${applied} skipped=${skipped} last_line=${lastLine} last_hash=${prevHash}`)
  if (json) {
    console.log(JSON.stringify({ applied, skipped, last_line: lastLine, last_hash: prevHash, skips }))
  }
  if (skipped > 0) {
    console.error(`FAIL: ${skipped} invalid line(s)`)
    process.exit(1)
  }
  console.log(`OK: every line valid, chain intact back to genesis`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
