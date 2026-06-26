# Stellar Document Verification System

A Soroban smart contract on Stellar testnet for registering, issuing, verifying, and revoking digital document certificates with multi-signature governance.

---

## Contract

| Field | Value |
|---|---|
| Network | Testnet |
| RPC | `https://soroban-testnet.stellar.org` |
| Contract ID | `CA6KYPPXEUTAP4X6JAEOI37OD2SCKEAUOSV2VN5ICDWCAI4WASFHRSYB` |
| WASM hash | `0f4bae0374cabe088f188087465ccc63e6d30b49a7a8038ae26624450eeefad7` |
| WASM size | 31,854 bytes |

### Deployment Transactions

| Step | Transaction Hash |
|---|---|
| Install WASM | `ca29d21f8b2b3d0908fa2e96548513afd41a15b6a4c11e453fb8993181f79ea6` |
| Deploy contract | `2492d22bf9e56ac14e47dc1b0047ade90d9b1456a933762a2956fdc8cbcba89a` |
| Init | `69b65967f97781d9385037dccb47a9cb9e6bc6b19a445eb3b702724a3c9bd9a2` |

---

## Roles

| Role | Who | What they can do |
|---|---|---|
| **Main Admin** | Contract owner | All admin functions, whitelist, sub-admins, issue certificates, ownership transfer, create proposals |
| **Sub-Admin** | Compliance officer | Review documents, create & approve proposals, cannot whitelist or issue certificates |
| **Whitelisted Company** | Trusted entity | Upload document hashes only |
| **Public** | Anyone | Read documents, verify certificates, view proposals and reviews |

---

## Accounts

| ID | Role | Public Key |
|---|---|---|
| wallet-01 | **Main Admin** | `GAKNE5M3T2OGH6VXEEEM2SWC7S7ZHSECVE2A5VPK7P55PAIVKEH7Z4NA` |
| wallet-02 | Sub-Admin A | `GAB6B3J2PE3NDVS4GZPJWHTSMYIFSTVIYRKOEYROPGM46A4YJCKCYKQW` |
| wallet-03 | Sub-Admin B | `GC6V6VZ6NGQO7A3TNMTOXLDBX3CZWCFRW2W57GSRM2KC7HUT7IISZJ3Z` |
| wallet-04 | Company A | `GBOMJW3SR76M4GZJA6E3HQOQZ2LZ6HCW5FIW6HWGT7OPXSWRBFZIZOOP` |
| wallet-05 | Company B | `GDP2SIFL3HQNSF74V6VHF3RVGKWYG5VJ5NJJH2Y5YBCXFTOOBZYLUKNA` |
| wallet-06 | Stranger (unauthorized) | `GD2YVC4AIW5QCXLJNTENB56ACLSLFGWZNYS7N5LHY4ML5TJARQFNOEDW` |
| wallet-10 | Sub-Admin C (extra) | `GBXR4AD4S5QEVLBCWFAI2KOZQUDO3WUSRD6AHLDZ5X3E6RTVJ3B2GXLG` |

---

## Certificate Lifecycle

```
  Submitted ──▶ Issued ──▶ Revoked
                    │
                    ▼
                 Expired (computed on verification)
```

- **Submitted**: Document hash registered on-chain. Not yet verifiable.
- **Issued**: Admin issues the certificate with an expiry timestamp. Verifiable.
- **Revoked**: Certificate revoked via governance multi-sig proposal. Document stays on-chain.
- **Expired**: Computed at verification time — if current ledger time exceeds the set expiry, the certificate is reported as Expired.

---

## Functions

### Initialization

| Function | Parameters | Auth | Description |
|---|---|---|---|
| `init` | `main_admin: Address` | None (one-time) | Sets contract owner and governance threshold to 1 |

### Admin Queries

| Function | Returns | Auth | Description |
|---|---|---|---|
| `main_admin_address` | `Address` | Public | Current contract owner |
| `governance_threshold` | `u32` | Public | Number of approvals needed for a proposal |

### Sub-Admin Management (Main Admin only)

| Function | Parameters | Description |
|---|---|---|
| `add_sub_admin` | `admin, sub_admin` | Register a compliance officer |
| `remove_sub_admin` | `admin, sub_admin` | Revoke compliance officer access |
| `is_sub_admin_public` | `addr: Address` | Check if address is a sub-admin (public) |

### Whitelist Management (Main Admin only)

| Function | Parameters | Description |
|---|---|---|
| `whitelist_address` | `address` | Add company to upload whitelist |
| `remove_from_whitelist` | `address` | Remove company from whitelist |
| `is_whitelisted` | `address` | Check whitelist status (public) |

### Threshold Management (Main Admin only)

| Function | Parameters | Description |
|---|---|---|
| `set_threshold` | `admin, new_threshold` | Change governance approval threshold |

### Document Storage

| Function | Parameters | Auth | Description |
|---|---|---|---|
| `store_document` | `actor, name, hash` | Main admin or whitelisted company | Register document hash as **Submitted** |
| `read_document` | `hash` | Public | Returns full document record including status and expiry |
| `issue_certificate` | `admin, doc_hash, expiry` | Main admin only | Transition document from Submitted → Issued with expiry |
| `verify_document` | `hash` | Public | Returns `verified_document` (bool), `certificate_status`, `expiry` |

### Compliance Reviews

| Function | Parameters | Auth | Description |
|---|---|---|---|
| `submit_review` | `sub_admin, doc_hash, status, score, comment_hash` | Sub-admin only | Submit compliance review (status: Approved, ApprovedWithRecommendations, RequiresChanges, Rejected) |
| `read_review` | `doc_hash, reviewer` | Public | Read a specific review |

### Multi-Sig Governance

| Function | Parameters | Auth | Description |
|---|---|---|---|
| `create_proposal` | `proposer, action` | Main admin or sub-admin | Create governance proposal. Returns proposal ID |
| `approve_proposal` | `sub_admin, proposal_id` | Sub-admin only | Approve proposal. Auto-executes when threshold met |
| `read_proposal` | `proposal_id` | Public | Return proposal record |

### Proposal Actions

| Action | Payload | Effect |
|---|---|---|
| `RevokeCertificate` | `doc_hash: String` | Marks certificate as Revoked (does not delete) |
| `UpdateThreshold` | `new_threshold: u32` | Changes approval threshold |
| `ContractUpgrade` | `wasm_hash: BytesN<32>` | Upgrades contract WASM via `update_current_contract_wasm` |

### Ownership Transfer

| Function | Parameters | Auth | Description |
|---|---|---|---|
| `transfer_main_admin` | `new_admin` | Current admin only | Transfer contract ownership |

---

## Enum Types

### `CertificateStatus` (document lifecycle)

```
Submitted | Issued | Revoked | Expired
```

### `DocumentStatus` (compliance review)

```
Approved | ApprovedWithRecommendations | RequiresChanges | Rejected
```

### `ProposalAction`

```
RevokeCertificate(String) | UpdateThreshold(u32) | ContractUpgrade(BytesN<32>)
```

---

## Comprehensive Test Results

All **63 tests** pass on Stellar testnet. Test file: `scripts/test_full.mjs`

### Category Summary

| Category | Tests | Result |
|---|---|---|
| 1. Initial State | 4 | ✅ All pass |
| 2. Sub-Admin Management | 6 | ✅ All pass |
| 3. Whitelist Management | 5 | ✅ All pass |
| 4. Threshold Management | 3 | ✅ All pass |
| 5. Document Storage | 7 | ✅ All pass |
| 6. Certificate Issuance | 5 | ✅ All pass |
| 7. Document Verification | 3 | ✅ All pass |
| 8. Compliance Reviews | 5 | ✅ All pass |
| 9. RevokeCertificate via Multi-Sig | 12 | ✅ All pass |
| 10. UpdateThreshold Proposal | 1 | ✅ All pass |
| 11. ContractUpgrade Proposal | 1 | ✅ All pass |
| 12. Ownership Transfer | 3 | ✅ All pass |
| 13. Public Read Access | 8 | ✅ All pass |

### Edge Cases Tested

| Edge Case | Expected Behavior | Verified |
|---|---|---|
| Store duplicate hash | Panic (already registered) | ✅ |
| Store as non-whitelisted user | Panic (not authorized) | ✅ |
| Verify non-existent doc | Returns null | ✅ |
| Verify Submitted doc | `verified_document=false`, status=Submitted | ✅ |
| Verify Issued doc | `verified_document=true`, status=Issued | ✅ |
| Verify Revoked doc | `verified_document=false`, status=Revoked | ✅ |
| Issue already-issued cert | Panic (only from Submitted) | ✅ |
| Issue non-existent doc | Panic (not found) | ✅ |
| Non-admin issues cert | Panic (only main admin) | ✅ |
| Non-admin adds sub-admin | Panic (only main admin) | ✅ |
| Non-admin whitelists | Panic (only main admin) | ✅ |
| Non-admin sets threshold | Panic (only main admin) | ✅ |
| Non-admin creates proposal | Panic (admin or sub-admin only) | ✅ |
| Non-sub-admin approves | Panic (sub-admin only) | ✅ |
| Same sub-admin double-approve | Panic (already approved) | ✅ |
| Approve already-executed proposal | Panic (already executed) | ✅ |
| Transfer to same address | Panic (must be different) | ✅ |
| Non-sub-admin reviews | Panic (sub-admin only) | ✅ |
| Read non-existent document | Returns null | ✅ |
| Read non-existent review | Returns null | ✅ |
| Read non-existent proposal | Returns null | ✅ |
| Public read access (8 functions) | Anyone can read | ✅ |
| Revoke marks Revoked (not delete) | Doc stays in storage | ✅ |
| Ownership round-trip | Transfer works both ways | ✅ |
| ContractUpgrade proposal creation | Proposal stored correctly | ✅ |

---

## Error Messages

| Panic Message | Trigger |
|---|---|
| `contract not initialized` | Calling any function before `init` |
| `Document already registered` | Storing a document with an existing hash |
| `not authorized: only main admin or whitelisted address` | Non-whitelisted user stores document |
| `only main admin can manage sub-admins` | Non-admin adds/removes sub-admins |
| `only main admin can issue certificates` | Non-admin calls `issue_certificate` |
| `certificate can only be issued from Submitted status` | Issuing an already-issued/revoked doc |
| `document not found` | Issue, revoke, or review on non-existent doc |
| `only main admin can set threshold` | Non-admin calls `set_threshold` |
| `not authorized: only sub-admins can submit reviews` | Non-sub-admin calls `submit_review` |
| `only main admin or sub-admin can create proposals` | Unauthorized user creates proposal |
| `only sub-admins can approve proposals` | Non-sub-admin approves proposal |
| `proposal not found` | Approve or read non-existent proposal |
| `proposal already executed` | Approve an already-executed proposal |
| `already approved by this sub-admin` | Same sub-admin approves twice |
| `new admin must be different` | Transfer to the same address |

---

## Architecture

- **Written in Rust** using `soroban-sdk = "27.0.0-rc.1"`
- **Storage**: All persistent using `env.storage().persistent()` — no temp or instance storage
- **No file storage**: Only SHA-256 hashes stored on-chain. Files remain off-chain.
- **Auto-execution**: Proposals execute automatically when approval threshold is met
- **Separation of powers**: Uploaders cannot review. Reviewers cannot issue certificates. Single sub-admin cannot revoke unilaterally.
- **Certificate lifecycle**: Documents progress through Submitted → Issued → Revoked. Expiry is computed at verification time.
