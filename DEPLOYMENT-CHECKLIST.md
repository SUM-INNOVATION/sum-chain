# Schema Validation Deployment Checklist

## Pre-Deployment

### Code Preparation
- [ ] Set activation_height in [schema_validator.rs](crates/state/src/schema_validator.rs#L50-L60)
  - Current block height: ___________
  - Chosen activation height: ___________ (recommend: current + 1000 blocks)
- [ ] Build release binary: `cargo build --release`
- [ ] Verify binary: `ls -lh target/release/sumchain-node`

### Communication
- [ ] Send [DEPLOYMENT-ANNOUNCEMENT.md](DEPLOYMENT-ANNOUNCEMENT.md) to verification team
- [ ] Announce activation height to all stakeholders
- [ ] Set deployment window with validator operators

---

## Deployment Day

### Validator 1

**Preparation:**
- [ ] Check current block height and sync status
- [ ] Backup current binary: `sudo cp /usr/local/bin/sumchain-node /usr/local/bin/sumchain-node.backup`

**Deployment:**
- [ ] Stop validator: `sudo systemctl stop sumchain-validator`
- [ ] Replace binary: `sudo cp target/release/sumchain-node /usr/local/bin/sumchain-node`
- [ ] Verify version: `/usr/local/bin/sumchain-node --version`
- [ ] Start validator: `sudo systemctl start sumchain-validator`

**Verification:**
- [ ] Check process running: `ps aux | grep sumchain-node`
- [ ] Monitor logs: `tail -f /var/log/sumchain/node.log`
- [ ] Verify RPC responding: `curl -X POST https://rpc.sum-chain.xyz -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`
- [ ] Watch for errors in logs (15 minutes)

### Validator 2

**Wait for Validator 1 to stabilize (15+ minutes), then:**

- [ ] Check current block height and sync status
- [ ] Backup current binary: `sudo cp /usr/local/bin/sumchain-node /usr/local/bin/sumchain-node.backup`
- [ ] Stop validator: `sudo systemctl stop sumchain-validator`
- [ ] Replace binary: `sudo cp target/release/sumchain-node /usr/local/bin/sumchain-node`
- [ ] Verify version: `/usr/local/bin/sumchain-node --version`
- [ ] Start validator: `sudo systemctl start sumchain-validator`

**Verification:**
- [ ] Check process running: `ps aux | grep sumchain-node`
- [ ] Monitor logs: `tail -f /var/log/sumchain/node.log`
- [ ] Verify RPC responding
- [ ] Watch for errors in logs (15 minutes)

---

## Post-Deployment Testing

### Before Activation Height

**Test 1: Old-style credential should SUCCEED (validation not active yet)**
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

**Expected**: ✅ Success (validation not active yet)

- [ ] Test passed
- [ ] Current block height: ___________
- [ ] Blocks until activation: ___________

### After Activation Height

**Wait until block height reaches activation_height, then test:**

**Test 2: Invalid credential should be REJECTED**
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

**Expected**: ❌ Error: `"Schema validation failed: Disallowed attribute key 'student_name'"`

- [ ] Test passed
- [ ] Error message correct

**Test 3: Valid credential should SUCCEED**
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

**Expected**: ✅ Success

- [ ] Test passed
- [ ] Credential created successfully

---

## Monitoring (First 24 Hours)

### System Health
- [ ] Both validators syncing/producing blocks
- [ ] No consensus failures or forks
- [ ] RPC endpoints responsive
- [ ] No unexpected errors in logs

### Schema Validation
- [ ] Valid credentials accepted
- [ ] Invalid credentials rejected with clear errors
- [ ] No false positives (valid credentials rejected)
- [ ] No false negatives (invalid credentials accepted)

### Error Tracking
- [ ] Monitor rejection rate
- [ ] Document common validation errors
- [ ] Provide guidance to issuers encountering errors

---

## Rollback Plan (If Needed)

**If critical issues occur:**

### Quick Rollback (Both Validators)
```bash
# Stop service
sudo systemctl stop sumchain-validator

# Restore old binary
sudo cp /usr/local/bin/sumchain-node.backup /usr/local/bin/sumchain-node

# Start service
sudo systemctl start sumchain-validator

# Verify
tail -f /var/log/sumchain/node.log
```

- [ ] Rollback executed on Validator 1
- [ ] Rollback executed on Validator 2
- [ ] Both validators syncing normally
- [ ] Issue documented for investigation

### Alternative: Disable Validation (Without Rollback)

If you need to disable validation without full rollback:

1. Edit [schema_validator.rs](crates/state/src/schema_validator.rs):
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

2. Rebuild and redeploy as above

---

## Final Confirmation

### Deployment Success Criteria
- [ ] Both validators running new binary
- [ ] Validation active after activation_height
- [ ] Invalid credentials rejected
- [ ] Valid credentials accepted
- [ ] No chain disruption
- [ ] Verification team notified of activation

### Sign-off
- Validator 1 operator: _________________ Date: _______
- Validator 2 operator: _________________ Date: _______
- Chain operator: _______________________ Date: _______

---

**Deployment Version**: 1.0
**Checklist Date**: 2026-02-01
**Schema Validation Version**: SRC-810/811/812 v1.0
