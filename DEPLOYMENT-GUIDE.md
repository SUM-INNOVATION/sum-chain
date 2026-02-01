# Schema Validation Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying schema validation (SRC-810/811/812, SRC-88X, SRC-87X, SRC-82X) to your validator nodes.

**Key Features Being Deployed:**
- Hard rejection of PII in academic credentials (SRC-81X)
- Native encryption metadata support for private credentials
- Employment credential validation (SRC-88X)
- Healthcare membership validation (SRC-87X)
- Tax disclosure validation (SRC-82X)

**Deployment Strategy:**
- Build on each validator device directly
- Sequential deployment (Validator 1, then Validator 2)
- Zero-downtime activation via `activation_height`

---

## Pre-Deployment Preparation

### 1. Set Activation Height

Before deploying, you need to set the activation height in the code.

**On your development machine:**

Edit [crates/state/src/schema_validator.rs](crates/state/src/schema_validator.rs#L50-L60):

```rust
impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            activation_height: 50000,  // CHANGE THIS VALUE
        }
    }
}
```

**Choosing activation_height:**
1. Check current block height: `curl -X POST https://rpc.sum-chain.xyz -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`
2. Add buffer for deployment: `activation_height = current_height + 1000` (approximately 1-2 hours)
3. Update the value in `schema_validator.rs`
4. Commit the change: `git add . && git commit -m "Set activation_height for schema validation deployment"`
5. Push to repository: `git push origin main`

### 2. Notify Stakeholders

Send [DEPLOYMENT-ANNOUNCEMENT.md](DEPLOYMENT-ANNOUNCEMENT.md) to:
- Verification team
- Academic credential issuers
- Any active integrators

Include:
- Activation block height
- Expected activation time (approximate)
- Links to documentation

---

## Deployment Steps

### Validator 1 Deployment

#### Step 1: SSH into Validator 1

```bash
ssh validator1.sum-chain.xyz
# Or use your validator's hostname/IP
```

#### Step 2: Navigate to Repository

```bash
cd /path/to/sumchain-node
# Adjust path based on your setup
```

#### Step 3: Pull Latest Code

```bash
git fetch origin
git pull origin main
```

Verify the activation_height is correct:
```bash
grep -A 5 "impl Default for ValidationConfig" crates/state/src/schema_validator.rs
```

#### Step 4: Build Release Binary

```bash
cargo build --release
```

**Expected build time:** 5-15 minutes depending on hardware.

**Verify build succeeded:**
```bash
ls -lh target/release/sumchain-node
# Should show the binary with recent timestamp
```

#### Step 5: Backup Current Binary

```bash
sudo cp /usr/local/bin/sumchain-node /usr/local/bin/sumchain-node.backup-$(date +%Y%m%d)
```

Verify backup:
```bash
ls -lh /usr/local/bin/sumchain-node*
```

#### Step 6: Stop Validator Service

```bash
sudo systemctl stop sumchain
```

**Verify service stopped:**
```bash
sudo systemctl status sumchain
# Should show "inactive (dead)"
```

#### Step 7: Replace Binary

```bash
sudo cp target/release/sumchain-node /usr/local/bin/sumchain-node
```

**Verify binary replaced:**
```bash
ls -lh /usr/local/bin/sumchain-node
/usr/local/bin/sumchain-node --version  # Optional: verify version
```

#### Step 8: Start Validator Service

```bash
sudo systemctl start sumchain
```

**Verify service started:**
```bash
sudo systemctl status sumchain
# Should show "active (running)"
```

#### Step 9: Monitor Logs

```bash
sudo journalctl -u sumchain -f
# Or, if using file-based logging:
# tail -f /var/log/sumchain/node.log
```

**Watch for:**
- ✅ "Validator started successfully"
- ✅ Block sync resuming
- ✅ No error messages
- ❌ Any crashes or panics (if seen, investigate immediately)

**Monitor for 15 minutes** before proceeding to Validator 2.

#### Step 10: Verify RPC Responding

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Expected response:
```json
{"jsonrpc":"2.0","id":1,"result":"0xXXXX"}
```

**Note current block height for reference.**

---

### Validator 2 Deployment

**IMPORTANT:** Only proceed after Validator 1 has been stable for 15+ minutes.

Repeat all steps from Validator 1:

```bash
# SSH into Validator 2
ssh validator2.sum-chain.xyz

# Navigate to repository
cd /path/to/sumchain-node

# Pull latest code
git fetch origin
git pull origin main

# Build
cargo build --release

# Backup
sudo cp /usr/local/bin/sumchain-node /usr/local/bin/sumchain-node.backup-$(date +%Y%m%d)

# Stop service
sudo systemctl stop sumchain

# Replace binary
sudo cp target/release/sumchain-node /usr/local/bin/sumchain-node

# Start service
sudo systemctl start sumchain

# Monitor
sudo journalctl -u sumchain -f
```

Monitor for 15 minutes and verify both validators are producing blocks.

---

## Post-Deployment Verification

### Before Activation Height

**Test that old-style credentials still work (validation not active yet):**

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "attributes": [
          {"name": "student_name", "value": "Test Student"}
        ]
      }
    }],
    "id": 1
  }'
```

**Expected:** ✅ Success (validation not active until activation_height)

### After Activation Height

**Monitor current block height:**
```bash
watch -n 10 'curl -s -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}" \
  | jq -r ".result" | xargs printf "%d\n"'
```

**Once block height >= activation_height, test validation:**

#### Test 1: Invalid Credential Should Be REJECTED

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "attributes": [
          {"name": "student_name", "value": "Test Student"}
        ]
      }
    }],
    "id": 1
  }'
```

**Expected:** ❌ Error: `"Schema validation failed: Disallowed attribute key 'student_name'"`

#### Test 2: Valid Credential Should SUCCEED

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "title": "Academic Transcript",
        "attributes": [
          {"name": "pdf_cid", "value": "bafybeig..."},
          {"name": "courses_commitment", "value": "blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"}
        ]
      },
      "payload_hint": "bafybeig..."
    }],
    "id": 1
  }'
```

**Expected:** ✅ Success

#### Test 3: Valid Encrypted Credential Should SUCCEED

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "title": "Academic Transcript (Encrypted)",
        "attributes": [
          {"name": "courses_commitment", "value": "blake3:a7f2c9e1d8b5..."}
        ]
      },
      "payload_hint": "bafybeig...encrypted",
      "encryption_meta": {
        "algorithm": "X25519Aes256Gcm",
        "key_commitment": "0x1234...",
        "nonce": [1,2,3,4,5,6,7,8,9,10,11,12]
      }
    }],
    "id": 1
  }'
```

**Expected:** ✅ Success (native encryption support)

---

## Monitoring (First 24 Hours)

### System Health Checks

```bash
# Check both validators are running
sudo systemctl status sumchain

# Monitor block production
watch -n 5 'curl -s -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}"'

# Watch for errors in logs
sudo journalctl -u sumchain -f --since "1 hour ago" | grep -i "error\|panic\|validation"
```

### Validation Metrics

Monitor for:
- Valid credentials being accepted
- Invalid credentials being rejected with clear error messages
- No false positives (valid credentials rejected)
- No false negatives (invalid credentials accepted)

---

## Rollback Procedure (If Needed)

If critical issues occur after deployment:

### Quick Rollback (Per Validator)

```bash
# Stop service
sudo systemctl stop sumchain

# Restore backup binary
sudo cp /usr/local/bin/sumchain-node.backup-YYYYMMDD /usr/local/bin/sumchain-node

# Start service
sudo systemctl start sumchain

# Verify
sudo systemctl status sumchain
sudo journalctl -u sumchain -f
```

### Disable Validation (Without Binary Rollback)

If you need to disable validation without full rollback:

1. Edit `crates/state/src/schema_validator.rs`:
```rust
impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: false,  // DISABLE
            activation_height: 50000,
        }
    }
}
```

2. Rebuild and redeploy using steps above

---

## Troubleshooting

### Service Won't Start

```bash
# Check detailed error logs
sudo journalctl -u sumchain -n 100 --no-pager

# Check binary permissions
ls -l /usr/local/bin/sumchain-node

# Verify binary is executable
sudo chmod +x /usr/local/bin/sumchain-node
```

### Build Failures

```bash
# Clean build cache
cargo clean

# Retry build
cargo build --release

# If dependencies fail, update Cargo.lock
cargo update
```

### Validators Out of Sync

```bash
# Check network connectivity between validators
ping validator2.sum-chain.xyz

# Verify both validators see same block height
curl -s -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

---

## Success Criteria

- ✅ Both validators running new binary
- ✅ No chain disruption during deployment
- ✅ Both validators syncing and producing blocks
- ✅ Validation active after activation_height
- ✅ Invalid credentials rejected with clear errors
- ✅ Valid credentials (including encrypted) accepted
- ✅ No unexpected errors in logs for 24 hours

---

## Documentation References

- [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) - Complete implementation guide for credential issuers
- [SRC-81X-COMMITMENT-CANONICALIZATION.md](SRC-81X-COMMITMENT-CANONICALIZATION.md) - Hashing specification
- [DEPLOYMENT-CHECKLIST.md](DEPLOYMENT-CHECKLIST.md) - Detailed deployment checklist
- [DEPLOYMENT-ANNOUNCEMENT.md](DEPLOYMENT-ANNOUNCEMENT.md) - Stakeholder communication template

---

## Support

**Issues during deployment:**
- Check logs: `sudo journalctl -u sumchain -f`
- Review troubleshooting section above
- Contact chain operator team

**Post-deployment support:**
- Monitor validation rejection rates
- Document common errors from issuers
- Provide guidance via VERIFICATION-TEAM-SUMMARY.md

---

**Document Version**: 1.0
**Date**: 2026-02-01
**Status**: Production-Ready
**Deployment Type**: Sequential validator upgrade with activation height
