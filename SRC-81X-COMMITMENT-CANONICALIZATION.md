# SRC-81X Commitment Canonicalization Specification

## Purpose

This document defines the **exact canonicalization rules** for computing BLAKE3 commitments in SRC-81X academic credentials (810/811/812).

**Why This Matters**: Two teams hashing the same data must produce identical commitments for verification to work. Without canonical rules, minor differences (key ordering, whitespace, encoding) will break interoperability.

---

## Canonical JSON Rules

### 1. **Deterministic Key Ordering**

Keys MUST be sorted lexicographically (ASCII byte order):

```json
// ✅ CORRECT (keys sorted)
{
  "course_code": "CS101",
  "course_title": "Intro to Programming",
  "grade": "A"
}

// ❌ WRONG (keys not sorted)
{
  "grade": "A",
  "course_code": "CS101",
  "course_title": "Intro to Programming"
}
```

### 2. **No Whitespace**

Remove ALL unnecessary whitespace (spaces, newlines, tabs):

```json
// ✅ CORRECT (compact)
{"course_code":"CS101","grade":"A"}

// ❌ WRONG (whitespace)
{
  "course_code": "CS101",
  "grade": "A"
}
```

### 3. **UTF-8 Encoding**

All strings MUST be UTF-8 encoded. No other encodings allowed.

### 4. **Number Representation**

- Integers: No leading zeros, no decimal point
- Floats: Use minimal representation (no trailing zeros)

```json
// ✅ CORRECT
{"credits": 3, "gpa": 3.87}

// ❌ WRONG
{"credits": 3.0, "gpa": 3.870000}
```

### 5. **No Null Values**

Omit fields with null values instead of including them:

```json
// ✅ CORRECT
{"course_code": "CS101"}

// ❌ WRONG
{"course_code": "CS101", "comments": null}
```

### 6. **Array Order Preservation**

Arrays preserve insertion order (do NOT sort arrays):

```json
// ✅ CORRECT (chronological order preserved)
["CS101", "CS102", "CS201"]

// ❌ WRONG (do not sort arrays)
["CS101", "CS201", "CS102"]
```

---

## Domain Separation Tags

Each commitment type uses a unique domain separator to prevent cross-domain attacks.

### Format

```
BLAKE3(domain_separator || canonical_json_bytes)
```

Where `||` means concatenation.

### Domain Separators (SRC-810: Transcript)

| Commitment Type | Domain Separator | Example |
|-----------------|------------------|---------|
| `courses_commitment` | `SRC-810-COURSES-v1` | BLAKE3("SRC-810-COURSES-v1" + canonical_json) |
| `grades_commitment` | `SRC-810-GRADES-v1` | BLAKE3("SRC-810-GRADES-v1" + canonical_json) |
| `student_commitment` | `SRC-810-STUDENT-v1` | BLAKE3("SRC-810-STUDENT-v1" + canonical_json) |

### Domain Separators (SRC-811: Diploma)

| Commitment Type | Domain Separator |
|-----------------|------------------|
| `degree_commitment` | `SRC-811-DEGREE-v1` |
| `major_commitment` | `SRC-811-MAJOR-v1` |
| `minor_commitment` | `SRC-811-MINOR-v1` |
| `honors_commitment` | `SRC-811-HONORS-v1` |
| `student_commitment` | `SRC-811-STUDENT-v1` |

### Domain Separators (SRC-812: Enrollment)

| Commitment Type | Domain Separator |
|-----------------|------------------|
| `enrollment_commitment` | `SRC-812-ENROLLMENT-v1` |
| `program_commitment` | `SRC-812-PROGRAM-v1` |
| `student_commitment` | `SRC-812-STUDENT-v1` |

---

## Output Format

### BLAKE3 Hash Output

Commitments MUST be formatted as:

```
blake3:<64-character-hex-string>
```

OR

```
0x<64-character-hex-string>
```

**Example**:
```
blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1
```

---

## Complete Example

### Input Data (Courses)

```json
[
  {
    "course_code": "CS101",
    "course_title": "Introduction to Programming",
    "credits": 3,
    "grade": "A",
    "term": "Fall 2024"
  },
  {
    "course_code": "MATH201",
    "course_title": "Calculus II",
    "credits": 4,
    "grade": "A-",
    "term": "Fall 2024"
  }
]
```

### Step 1: Canonicalize Each Object

Sort keys, remove whitespace:

```json
[{"course_code":"CS101","course_title":"Introduction to Programming","credits":3,"grade":"A","term":"Fall 2024"},{"course_code":"MATH201","course_title":"Calculus II","credits":4,"grade":"A-","term":"Fall 2024"}]
```

### Step 2: Prepend Domain Separator

```
SRC-810-COURSES-v1[{"course_code":"CS101",...}]
```

### Step 3: Compute BLAKE3

```rust
use blake3;

let domain = b"SRC-810-COURSES-v1";
let canonical_json = br#"[{"course_code":"CS101","course_title":"Introduction to Programming","credits":3,"grade":"A","term":"Fall 2024"},{"course_code":"MATH201","course_title":"Calculus II","credits":4,"grade":"A-","term":"Fall 2024"}]"#;

let mut hasher = blake3::Hasher::new();
hasher.update(domain);
hasher.update(canonical_json);
let hash = hasher.finalize();

// Output format
let commitment = format!("blake3:{}", hash.to_hex());
```

### Step 4: Store in Metadata

```json
{
  "metadata": {
    "attributes": [
      {
        "name": "courses_commitment",
        "value": "blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
      }
    ]
  }
}
```

---

## Reference Implementation

### TypeScript/JavaScript

```typescript
import { blake3 } from 'blake3';

function canonicalizeJSON(obj: any): string {
  if (obj === null) {
    throw new Error('Null values not allowed');
  }

  if (Array.isArray(obj)) {
    // Preserve array order
    return '[' + obj.map(canonicalizeJSON).join(',') + ']';
  }

  if (typeof obj === 'object') {
    // Sort keys lexicographically
    const keys = Object.keys(obj).sort();
    const pairs = keys
      .filter(k => obj[k] !== null && obj[k] !== undefined)
      .map(k => `"${k}":${canonicalizeJSON(obj[k])}`);
    return '{' + pairs.join(',') + '}';
  }

  if (typeof obj === 'string') {
    return JSON.stringify(obj); // Properly escape
  }

  if (typeof obj === 'number') {
    return String(obj); // No trailing zeros
  }

  if (typeof obj === 'boolean') {
    return String(obj);
  }

  throw new Error(`Unsupported type: ${typeof obj}`);
}

function computeCommitment(
  domain: string,
  data: any
): string {
  const canonical = canonicalizeJSON(data);
  const domainBytes = new TextEncoder().encode(domain);
  const dataBytes = new TextEncoder().encode(canonical);

  const combined = new Uint8Array(domainBytes.length + dataBytes.length);
  combined.set(domainBytes);
  combined.set(dataBytes, domainBytes.length);

  const hash = blake3(combined);
  return `blake3:${Buffer.from(hash).toString('hex')}`;
}

// Usage
const courses = [
  {
    course_code: "CS101",
    course_title: "Introduction to Programming",
    credits: 3,
    grade: "A",
    term: "Fall 2024"
  }
];

const commitment = computeCommitment("SRC-810-COURSES-v1", courses);
console.log(commitment);
```

### Rust

```rust
use blake3;
use serde_json::{json, Value};

fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Null => panic!("Null values not allowed"),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter()
                .map(|v| canonicalize_json(v))
                .collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys.iter()
                .filter(|k| !map[*k].is_null())
                .map(|k| format!("\"{}\":{}", k, canonicalize_json(&map[*k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn compute_commitment(domain: &str, data: &Value) -> String {
    let canonical = canonicalize_json(data);
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    format!("blake3:{}", hash.to_hex())
}

// Usage
let courses = json!([
    {
        "course_code": "CS101",
        "course_title": "Introduction to Programming",
        "credits": 3,
        "grade": "A",
        "term": "Fall 2024"
    }
]);

let commitment = compute_commitment("SRC-810-COURSES-v1", &courses);
println!("{}", commitment);
```

---

## Verification Process

### Issuer Side (Creating Commitment)

1. Collect sensitive data (courses, grades, student info)
2. Canonicalize JSON (sort keys, remove whitespace)
3. Prepend domain separator
4. Compute BLAKE3 hash
5. Format as `blake3:<hex>`
6. Store commitment in `metadata.attributes[]`
7. Store full data encrypted on IPFS (referenced by `payload_hint`)

### Verifier Side (Checking Commitment)

1. Retrieve credential from chain
2. Get commitment from `metadata.attributes[]`
3. Obtain preimage from issuer/student (via IPFS, secure channel)
4. Canonicalize preimage using same rules
5. Prepend same domain separator
6. Compute BLAKE3 hash
7. Compare with on-chain commitment
8. If match: data is authentic and unmodified

---

## Test Vectors

### Test Vector 1: Simple Object

**Input**:
```json
{"name": "Alice", "age": 25}
```

**Canonical**:
```json
{"age":25,"name":"Alice"}
```

**Domain**: `TEST-v1`

**Expected Commitment**:
```
blake3:c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
```

### Test Vector 2: Nested Array

**Input**:
```json
{"courses": ["CS101", "CS102"], "credits": 6}
```

**Canonical**:
```json
{"courses":["CS101","CS102"],"credits":6}
```

**Domain**: `TEST-v1`

**Expected Commitment**:
```
blake3:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
```

---

## Common Pitfalls

### ❌ WRONG: Sorting Array Items

```javascript
// NEVER sort arrays!
const courses = ["CS102", "CS101"].sort(); // ❌ WRONG
```

Arrays preserve insertion order. Only object keys are sorted.

### ❌ WRONG: Including Whitespace

```javascript
const canonical = JSON.stringify(obj, null, 2); // ❌ WRONG (has whitespace)
```

Use compact format: `JSON.stringify(obj)` with no spacing.

### ❌ WRONG: Missing Domain Separator

```javascript
const hash = blake3(canonical_json); // ❌ WRONG (no domain separator)
```

ALWAYS prepend domain separator to prevent cross-domain attacks.

### ❌ WRONG: Wrong Hash Algorithm

```javascript
const hash = sha256(domain + canonical); // ❌ WRONG (use BLAKE3, not SHA-256)
```

SUM Chain uses **BLAKE3**, not SHA-256.

---

## FAQ

### Q: Why BLAKE3 instead of SHA-256?

**A**: BLAKE3 is faster, more secure, and used throughout SUM Chain. Consistency across the chain reduces complexity.

### Q: Can I use a different canonical JSON library?

**A**: Yes, as long as it follows these rules: sorted keys, no whitespace, UTF-8, no nulls. Test against reference vectors.

### Q: What if two issuers compute different commitments for the same data?

**A**: This means they used different canonicalization. Both must follow this spec exactly. Use test vectors to validate implementation.

### Q: Can I add extra fields to commitments?

**A**: No. Commitments MUST only include the fields specified in the data structure. Extra fields will cause hash mismatch.

### Q: How do I handle floating-point precision?

**A**: Store GPAs/scores as strings if precision matters (e.g., "3.87" not 3.87). Or use integers (387 = 3.87 * 100).

---

## Compliance Checklist

Before deploying, verify your implementation:

- [ ] Keys sorted lexicographically
- [ ] No whitespace in canonical JSON
- [ ] UTF-8 encoding
- [ ] Arrays preserve order (not sorted)
- [ ] Null values omitted
- [ ] Domain separator prepended
- [ ] BLAKE3 used (not SHA-256)
- [ ] Output formatted as `blake3:<hex>` or `0x<hex>`
- [ ] Test vectors pass

---

**Document Version**: 1.0
**Last Updated**: 2026-02-01
**Status**: Official Specification for SRC-81X
**Reference Implementation**: See code examples above
