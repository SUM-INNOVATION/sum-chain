# SRC-81X Educational Credentials - Complete Guide

## Overview

SRC-81X is the standard for educational credentials on SUM Chain, built on the SRC-80X layered trust architecture. This guide covers:

1. Registering as an Educational Institution (SRC-802)
2. Creating Student Identities (SRC-801)
3. Issuing Enrollment Verifications (SRC-812)
4. Issuing Academic Transcripts (SRC-810)
5. Issuing Diplomas/Degrees (SRC-811)

---

## SRC-81X Standards

| Standard | Type | Purpose |
|----------|------|---------|
| **SRC-810** | Academic Transcript | Course records, grades, credits, GPA |
| **SRC-811** | Diploma/Degree | Bachelor's, Master's, PhD, certificates |
| **SRC-812** | Enrollment Verification | Current student status, enrollment dates |

All SRC-81X credentials require the issuer to be registered with `IssuerType: Educational`.

---

## Part 1: Register as Educational Institution

Educational institutions (universities, colleges, schools, certification bodies) must register before issuing credentials.

### Registration Requirements

- **Issuer Type**: `Educational` (value: 1)
- **Display Name**: Institution's official name (e.g., "Stanford University")
- **Jurisdiction**: ISO 3166-1 alpha-2 country code (e.g., "US", "GB", "CA")
- **Issuer Commitment**: 32-byte hash commitment to institution details
- **Policy ID**: 32-byte policy identifier (can be zeros for default)

### Python Script: Register Educational Institution

```python
#!/usr/bin/env python3
"""
Register as an educational institution (SRC-802 Issuer Registry)
"""
import requests
import hashlib

RPC_URL = "https://rpc.sum-chain.xyz"

def register_educational_institution(private_key_hex, institution_name, jurisdiction="US"):
    """
    Register an educational institution as an SRC-81X issuer

    Args:
        private_key_hex: 32-byte private key (hex string, 64 chars)
        institution_name: Official institution name (e.g., "Stanford University")
        jurisdiction: ISO 3166-1 alpha-2 country code
    """

    # Create issuer commitment (hash of institution details)
    commitment_data = f"{institution_name}|{jurisdiction}|EDUCATIONAL"
    issuer_commitment = hashlib.sha256(commitment_data.encode()).hexdigest()

    # Default policy ID (zeros) - can be customized for specific policies
    policy_id = "0" * 64

    request = {
        "private_key": private_key_hex,
        "issuer_type": "Educational",  # Must be "Educational" for SRC-81X
        "display_name": institution_name,
        "issuer_commitment": issuer_commitment,
        "jurisdiction_code": jurisdiction,
        "policy_id": policy_id
    }

    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_registerIssuer",
        "params": [request]
    })

    return response.json()

# Example usage
if __name__ == "__main__":
    # Your institution's private key (keep secure!)
    INSTITUTION_KEY = "your_private_key_hex_here"

    result = register_educational_institution(
        private_key_hex=INSTITUTION_KEY,
        institution_name="Stanford University",
        jurisdiction="US"
    )

    print(f"Registration result: {result}")
```

### Expected Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "tx_hash": "0x...",
    "issuer_address": "YourInstitutionAddress...",
    "error": null
  },
  "id": 1
}
```

---

## Part 2: Create Student Identity (Optional)

Students can create their own identity (SRC-801 Subject) to hold credentials.

### Python Script: Create Student Identity

```python
def create_student_identity(student_private_key_hex):
    """
    Create a decentralized identity for a student (SRC-801)

    This creates an on-chain identity anchor that can receive credentials
    """

    # Identity commitment (hash of student info - kept private)
    identity_data = f"student_identity_{student_private_key_hex[:16]}"
    identity_commitment = hashlib.sha256(identity_data.encode()).hexdigest()

    request = {
        "private_key": student_private_key_hex,
        "identity_commitment": identity_commitment,
        "recovery_addresses": []  # Optional recovery controllers
    }

    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_createIdentity",
        "params": [request]
    })

    return response.json()
```

---

## Part 3: Issue Enrollment Verification (SRC-812)

Verify that a student is currently enrolled.

### Enrollment Data Fields

- **Student Address**: Blockchain address of the student
- **Program**: Degree program (e.g., "Computer Science BS")
- **Enrollment Date**: Timestamp when student enrolled
- **Expected Graduation**: Expected graduation date (0 = ongoing)
- **Enrollment Status**: Active, On Leave, Graduated, Withdrawn

### Python Script: Issue Enrollment Verification

```python
def issue_enrollment_verification(
    issuer_private_key,
    student_address,
    program_name,
    enrollment_date,
    expected_graduation=0,
    status="Active"
):
    """
    Issue SRC-812 Enrollment Verification credential

    Args:
        issuer_private_key: Institution's private key (hex)
        student_address: Student's blockchain address (base58)
        program_name: Degree program (e.g., "Computer Science BS")
        enrollment_date: Unix timestamp (milliseconds)
        expected_graduation: Unix timestamp (milliseconds), 0 for ongoing
        status: "Active", "OnLeave", "Graduated", "Withdrawn"
    """

    # Create commitments for privacy
    student_ref = hashlib.sha256(student_address.encode()).hexdigest()
    program_ref = hashlib.sha256(program_name.encode()).hexdigest()
    enrollment_commitment = hashlib.sha256(str(enrollment_date).encode()).hexdigest()

    request = {
        "private_key": issuer_private_key,
        "credential_type": "EnrollmentVerification",  # SRC-812
        "subject_address": student_address,
        "subject_ref": student_ref,
        "program_ref": program_ref,
        "enrollment_commitment": enrollment_commitment,
        "valid_from": enrollment_date,
        "expiry": expected_graduation,  # 0 = no expiry
        "status": status,
        "policy_id": "0" * 64,
        "metadata": {
            "program": program_name,
            "credential_type": "enrollment"
        }
    }

    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    })

    return response.json()

# Example
result = issue_enrollment_verification(
    issuer_private_key="your_institution_key",
    student_address="StudentAddress123...",
    program_name="Computer Science BS",
    enrollment_date=1693939200000,  # Sep 6, 2023
    expected_graduation=1748822400000,  # June 1, 2025
    status="Active"
)
```

---

## Part 4: Issue Academic Transcript (SRC-810)

Academic transcripts contain course records, grades, and credits.

### Transcript Data Fields

- **Student Address**: Blockchain address of the student
- **Courses**: List of courses with grades and credits
- **GPA**: Cumulative grade point average
- **Credits Earned**: Total credits completed
- **Academic Period**: Semester/quarter information
- **Issue Date**: When transcript was issued

### Python Script: Issue Academic Transcript

```python
def issue_academic_transcript(
    issuer_private_key,
    student_address,
    courses,  # List of {course_code, course_name, grade, credits}
    gpa,
    total_credits,
    academic_period,
    issue_date
):
    """
    Issue SRC-810 Academic Transcript credential

    Args:
        issuer_private_key: Institution's private key (hex)
        student_address: Student's blockchain address (base58)
        courses: List of course dictionaries
        gpa: Cumulative GPA (e.g., 3.85)
        total_credits: Total credits earned (e.g., 120)
        academic_period: Semester info (e.g., "Fall 2024")
        issue_date: Unix timestamp (milliseconds)
    """

    # Create privacy-preserving commitments
    student_ref = hashlib.sha256(student_address.encode()).hexdigest()

    # Create transcript commitment (hash of all course data)
    transcript_data = f"{student_address}|{gpa}|{total_credits}|{academic_period}"
    for course in courses:
        transcript_data += f"|{course['course_code']}:{course['grade']}"
    transcript_commitment = hashlib.sha256(transcript_data.encode()).hexdigest()

    # GPA commitment for selective disclosure
    gpa_commitment = hashlib.sha256(str(gpa).encode()).hexdigest()

    request = {
        "private_key": issuer_private_key,
        "credential_type": "AcademicTranscript",  # SRC-810
        "subject_address": student_address,
        "subject_ref": student_ref,
        "transcript_commitment": transcript_commitment,
        "gpa_commitment": gpa_commitment,
        "valid_from": issue_date,
        "expiry": 0,  # Transcripts don't expire
        "policy_id": "0" * 64,
        "metadata": {
            "gpa": gpa,
            "total_credits": total_credits,
            "academic_period": academic_period,
            "courses": courses,  # Can be encrypted for privacy
            "credential_type": "transcript"
        }
    }

    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    })

    return response.json()

# Example
courses = [
    {"course_code": "CS101", "course_name": "Intro to CS", "grade": "A", "credits": 4},
    {"course_code": "MATH101", "course_name": "Calculus I", "grade": "A-", "credits": 4},
    {"course_code": "ENG101", "course_name": "English Comp", "grade": "B+", "credits": 3}
]

result = issue_academic_transcript(
    issuer_private_key="your_institution_key",
    student_address="StudentAddress123...",
    courses=courses,
    gpa=3.85,
    total_credits=120,
    academic_period="Fall 2024",
    issue_date=int(datetime.now().timestamp() * 1000)
)
```

---

## Part 5: Issue Diploma/Degree (SRC-811)

Issue official degree credentials (Bachelor's, Master's, PhD, certificates).

### Degree Data Fields

- **Student Address**: Blockchain address of the student
- **Degree Type**: BS, BA, MS, MA, MBA, PhD, Certificate
- **Major/Field**: Field of study (e.g., "Computer Science")
- **Honors**: Summa/Magna/Cum Laude, Dean's List, etc.
- **Graduation Date**: When degree was conferred
- **GPA**: Final cumulative GPA

### Python Script: Issue Diploma/Degree

```python
def issue_diploma(
    issuer_private_key,
    student_address,
    degree_type,  # "BS", "MS", "PhD", etc.
    major,
    graduation_date,
    gpa=None,
    honors=None
):
    """
    Issue SRC-811 Diploma/Degree credential

    Args:
        issuer_private_key: Institution's private key (hex)
        student_address: Student's blockchain address (base58)
        degree_type: "BS", "BA", "MS", "MA", "MBA", "PhD", "Certificate"
        major: Field of study (e.g., "Computer Science")
        graduation_date: Unix timestamp (milliseconds)
        gpa: Final cumulative GPA (optional)
        honors: "Summa Cum Laude", "Magna Cum Laude", etc. (optional)
    """

    # Create privacy-preserving commitments
    student_ref = hashlib.sha256(student_address.encode()).hexdigest()

    # Degree commitment
    degree_data = f"{student_address}|{degree_type}|{major}|{graduation_date}"
    if gpa:
        degree_data += f"|{gpa}"
    if honors:
        degree_data += f"|{honors}"
    degree_commitment = hashlib.sha256(degree_data.encode()).hexdigest()

    # Field commitment for selective disclosure
    field_commitment = hashlib.sha256(major.encode()).hexdigest()

    metadata = {
        "degree_type": degree_type,
        "major": major,
        "graduation_date_readable": datetime.fromtimestamp(graduation_date/1000).strftime("%B %d, %Y"),
        "credential_type": "diploma"
    }

    if gpa:
        metadata["gpa"] = gpa
    if honors:
        metadata["honors"] = honors

    request = {
        "private_key": issuer_private_key,
        "credential_type": "Diploma",  # SRC-811
        "subject_address": student_address,
        "subject_ref": student_ref,
        "degree_commitment": degree_commitment,
        "field_commitment": field_commitment,
        "valid_from": graduation_date,
        "expiry": 0,  # Degrees don't expire
        "policy_id": "0" * 64,
        "metadata": metadata
    }

    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    })

    return response.json()

# Example
from datetime import datetime

result = issue_diploma(
    issuer_private_key="your_institution_key",
    student_address="StudentAddress123...",
    degree_type="BS",
    major="Computer Science",
    graduation_date=int(datetime(2025, 6, 15).timestamp() * 1000),
    gpa=3.85,
    honors="Cum Laude"
)
```

---

## Complete Example: University Issuing All Credentials

```python
#!/usr/bin/env python3
"""
Complete example: Stanford University issuing SRC-81X credentials
"""
import requests
import hashlib
from datetime import datetime

RPC_URL = "https://rpc.sum-chain.xyz"
STANFORD_PRIVATE_KEY = "your_institution_private_key_here"

def main():
    print("=" * 60)
    print("Stanford University - SRC-81X Credential Issuance")
    print("=" * 60)

    # Student information
    student_address = "StudentAddress123..."

    # 1. Issue Enrollment Verification (SRC-812)
    print("\n1. Issuing Enrollment Verification...")
    enrollment_result = issue_enrollment_verification(
        issuer_private_key=STANFORD_PRIVATE_KEY,
        student_address=student_address,
        program_name="Computer Science BS",
        enrollment_date=int(datetime(2021, 9, 1).timestamp() * 1000),
        expected_graduation=int(datetime(2025, 6, 15).timestamp() * 1000),
        status="Active"
    )
    print(f"   ✓ Enrollment credential: {enrollment_result.get('result', {}).get('tx_hash')}")

    # 2. Issue Academic Transcript (SRC-810)
    print("\n2. Issuing Academic Transcript...")
    courses = [
        {"course_code": "CS106A", "course_name": "Programming Methodology", "grade": "A", "credits": 5},
        {"course_code": "CS107", "course_name": "Computer Organization", "grade": "A-", "credits": 5},
        {"course_code": "CS161", "course_name": "Design/Analysis Algorithms", "grade": "A", "credits": 5},
        {"course_code": "MATH51", "course_name": "Linear Algebra", "grade": "A", "credits": 5}
    ]

    transcript_result = issue_academic_transcript(
        issuer_private_key=STANFORD_PRIVATE_KEY,
        student_address=student_address,
        courses=courses,
        gpa=3.85,
        total_credits=180,
        academic_period="2021-2025",
        issue_date=int(datetime.now().timestamp() * 1000)
    )
    print(f"   ✓ Transcript credential: {transcript_result.get('result', {}).get('tx_hash')}")

    # 3. Issue Diploma (SRC-811)
    print("\n3. Issuing Diploma...")
    diploma_result = issue_diploma(
        issuer_private_key=STANFORD_PRIVATE_KEY,
        student_address=student_address,
        degree_type="BS",
        major="Computer Science",
        graduation_date=int(datetime(2025, 6, 15).timestamp() * 1000),
        gpa=3.85,
        honors="Cum Laude"
    )
    print(f"   ✓ Diploma credential: {diploma_result.get('result', {}).get('tx_hash')}")

    print("\n" + "=" * 60)
    print("All credentials issued successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---

## Verification and Querying

### Check if Institution Can Issue Credentials

```python
def can_institution_issue(institution_address, credential_type):
    """
    Check if an institution is authorized to issue a specific credential type
    """
    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_canIssue",
        "params": [institution_address, credential_type]
    })
    return response.json()

# Example
result = can_institution_issue(
    "StanfordAddress...",
    "Diploma"  # or "AcademicTranscript", "EnrollmentVerification"
)
print(f"Can issue: {result}")
```

### Get Student's Credentials

```python
def get_student_credentials(student_address):
    """
    Get all credentials held by a student
    """
    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_getCredentialsBySubject",
        "params": [student_address]
    })
    return response.json()

# Example
credentials = get_student_credentials("StudentAddress123...")
print(f"Student has {len(credentials.get('result', []))} credentials")
```

### Verify Credential Validity

```python
def verify_credential(credential_id):
    """
    Verify if a credential is still valid (not revoked/expired)
    """
    response = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_isCredentialValid",
        "params": [credential_id]
    })
    return response.json()
```

---

## Key Privacy Features

1. **Commitments**: Actual data (names, courses, grades) hashed for privacy
2. **Selective Disclosure**: Students can prove GPA > 3.5 without revealing exact GPA
3. **Unlinkability**: Credentials from different issuers can't be correlated
4. **ZK Proofs**: Prove properties without revealing underlying data

---

## Best Practices

1. **Secure Key Management**: Store institution private keys in HSMs or secure vaults
2. **Batch Issuance**: Issue credentials in batches to reduce transaction costs
3. **Metadata Encryption**: Encrypt sensitive metadata fields for additional privacy
4. **Credential Lifecycle**: Implement processes for updates and revocations
5. **Backup Policies**: Maintain off-chain backups of credential details

---

## Support and Resources

- **Documentation**: `/docs/SRC-80X-81X-DocClass.md`
- **RPC Endpoints**: `https://rpc.sum-chain.xyz`
- **Policy Account Guide**: `/docs/policy-accounts.md` (for multi-sig governance)

---

## License

This guide is released under CC0 1.0 Universal.
