#![cfg_attr(not(test), no_std)]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

#[contract]
pub struct Contract;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------
#[derive(Clone)]
#[contracttype]
enum DataKey {
    /// Persistent: single main-admin address
    MainAdmin,
    /// Persistent: number of approvals needed for a proposal to pass
    GovernanceThreshold,
    /// Persistent: monotonic counter for proposal IDs
    ProposalCount,
    /// Persistent: document by hash
    Document(String),
    /// Persistent: whitelisted document uploaders
    Whitelist(Address),
    /// Persistent: sub-admin membership
    SubAdmin(Address),
    /// Persistent: document review keyed by (doc_hash, sub_admin)
    DocumentReview(String, Address),
    /// Persistent: governance proposal by ID
    Proposal(u64),
}

// ---------------------------------------------------------------------------
// Document types
// ---------------------------------------------------------------------------
#[derive(Clone)]
#[contracttype]
pub struct Document {
    pub name: String,
    pub hash: String,
    pub timestamp: u64,
    pub added_by: Address,
    pub status: CertificateStatus,
    pub expiry: u64,
}

#[derive(Clone)]
#[contracttype]
pub struct VerifiedDocument {
    pub name: String,
    pub hash: String,
    pub timestamp: u64,
    pub added_by: Address,
    pub verified_document: bool,
    pub certificate_status: CertificateStatus,
    pub expiry: u64,
}

// ---------------------------------------------------------------------------
// Compliance / Review types
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[contracttype]
pub enum DocumentStatus {
    Approved,
    ApprovedWithRecommendations,
    RequiresChanges,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[contracttype]
pub enum CertificateStatus {
    Submitted,
    Issued,
    Revoked,
    Expired,
}

#[derive(Clone)]
#[contracttype]
pub struct Review {
    pub reviewer: Address,
    pub status: DocumentStatus,
    pub score: u32,
    pub comment_hash: String,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Multi-sig governance types
// ---------------------------------------------------------------------------
#[derive(Clone)]
#[contracttype]
pub enum ProposalAction {
    RevokeCertificate(String),
    UpdateThreshold(u32),
    ContractUpgrade(BytesN<32>),
}

#[derive(Clone)]
#[contracttype]
pub struct Proposal {
    pub id: u64,
    pub action: ProposalAction,
    pub approvals: Vec<Address>,
    pub executed: bool,
}

// ---------------------------------------------------------------------------
// Contract implementation
// ---------------------------------------------------------------------------
#[contractimpl]
impl Contract {
    // ---- Initialization ----

    /// One-time init. Sets the main admin and a default threshold of 1.
    pub fn init(env: Env, main_admin: Address) {
        env.storage().persistent().set(&DataKey::MainAdmin, &main_admin);
        env.storage()
            .persistent()
            .set(&DataKey::GovernanceThreshold, &1u32);
    }

    // ---- Internal helpers ----

    fn assert_main_admin(env: &Env) -> Address {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        admin.require_auth();
        admin
    }

    fn is_sub_admin(env: &Env, addr: &Address) -> bool {
        env.storage()
            .persistent()
            .get::<_, bool>(&DataKey::SubAdmin(addr.clone()))
            .unwrap_or(false)
    }

    fn assert_main_admin_or_whitelisted(env: &Env, actor: &Address) {
        actor.require_auth();
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if actor == &admin {
            return;
        }
        let allowed = env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::Whitelist(actor.clone()))
            .unwrap_or(false);
        if !allowed {
            panic!("not authorized: only main admin or whitelisted address");
        }
    }

    fn effective_certificate_status(env: &Env, doc: &Document) -> CertificateStatus {
        if doc.status == CertificateStatus::Issued && env.ledger().timestamp() > doc.expiry {
            CertificateStatus::Expired
        } else {
            doc.status
        }
    }

    fn execute_action(env: &Env, action: &ProposalAction) {
        match action {
            ProposalAction::RevokeCertificate(doc_hash) => {
                let key = DataKey::Document(doc_hash.clone());
                let mut doc: Document = env
                    .storage()
                    .persistent()
                    .get(&key)
                    .expect("document not found");
                doc.status = CertificateStatus::Revoked;
                env.storage().persistent().set(&key, &doc);
            }
            ProposalAction::UpdateThreshold(new_threshold) => {
                env.storage()
                    .persistent()
                    .set(&DataKey::GovernanceThreshold, new_threshold);
            }
            ProposalAction::ContractUpgrade(wasm_hash) => {
                env.deployer().update_current_contract_wasm(wasm_hash.clone());
            }
        }
    }

    // ---- Admin queries ----

    pub fn main_admin_address(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized")
    }

    pub fn governance_threshold(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::GovernanceThreshold)
            .unwrap_or(1)
    }

    // ---- Sub-admin management (main-admin only) ----

    pub fn add_sub_admin(env: Env, admin: Address, sub_admin: Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if admin != stored {
            panic!("only main admin can manage sub-admins");
        }
        env.storage()
            .persistent()
            .set(&DataKey::SubAdmin(sub_admin), &true);
    }

    pub fn remove_sub_admin(env: Env, admin: Address, sub_admin: Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if admin != stored {
            panic!("only main admin can manage sub-admins");
        }
        env.storage()
            .persistent()
            .remove(&DataKey::SubAdmin(sub_admin));
    }

    pub fn is_sub_admin_public(env: Env, addr: Address) -> bool {
        Self::is_sub_admin(&env, &addr)
    }

    // ---- Threshold management (main-admin only) ----

    pub fn set_threshold(env: Env, admin: Address, new_threshold: u32) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if admin != stored {
            panic!("only main admin can set threshold");
        }
        env.storage()
            .persistent()
            .set(&DataKey::GovernanceThreshold, &new_threshold);
    }

    // ---- Whitelist (main-admin only) ----

    pub fn whitelist_address(env: Env, address: Address) {
        let _admin = Self::assert_main_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Whitelist(address), &true);
    }

    pub fn remove_from_whitelist(env: Env, address: Address) {
        let _admin = Self::assert_main_admin(&env);
        env.storage()
            .persistent()
            .remove(&DataKey::Whitelist(address));
    }

    pub fn is_whitelisted(env: Env, address: Address) -> bool {
        env.storage()
            .persistent()
            .get::<_, bool>(&DataKey::Whitelist(address))
            .unwrap_or(false)
    }

    // ---- Document storage ----

    pub fn store_document(env: Env, actor: Address, name: String, hash: String) {
        let key = DataKey::Document(hash.clone());
        if env.storage().persistent().has(&key) {
            panic!("Document already registered");
        }
        Self::assert_main_admin_or_whitelisted(&env, &actor);
        let timestamp: u64 = env.ledger().timestamp();
        let doc = Document {
            name,
            hash: hash.clone(),
            timestamp,
            added_by: actor,
            status: CertificateStatus::Submitted,
            expiry: 0u64,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Document(hash), &doc);
    }

    pub fn issue_certificate(env: Env, admin: Address, doc_hash: String, expiry: u64) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if admin != stored {
            panic!("only main admin can issue certificates");
        }

        let key = DataKey::Document(doc_hash.clone());
        let mut doc: Document = env
            .storage()
            .persistent()
            .get(&key)
            .expect("document not found");

        if doc.status != CertificateStatus::Submitted {
            panic!("certificate can only be issued from Submitted status");
        }

        doc.status = CertificateStatus::Issued;
        doc.expiry = expiry;
        env.storage().persistent().set(&key, &doc);
    }

    pub fn read_document(env: Env, hash: String) -> Option<Document> {
        env.storage().persistent().get(&DataKey::Document(hash))
    }

    pub fn verify_document(env: Env, hash: String) -> Option<VerifiedDocument> {
        let doc: Option<Document> = env.storage().persistent().get(&DataKey::Document(hash));
        doc.map(|d| {
            let effective_status = Self::effective_certificate_status(&env, &d);
            let is_verified = effective_status == CertificateStatus::Issued;

            VerifiedDocument {
                name: d.name,
                hash: d.hash,
                timestamp: d.timestamp,
                added_by: d.added_by,
                verified_document: is_verified,
                certificate_status: effective_status,
                expiry: d.expiry,
            }
        })
    }

    // ---- Ownership transfer ----

    pub fn transfer_main_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        current.require_auth();
        if new_admin == current {
            panic!("new admin must be different");
        }
        env.storage().persistent().set(&DataKey::MainAdmin, &new_admin);
    }

    // ---- Compliance reviews (sub-admin only) ----

    pub fn submit_review(
        env: Env,
        sub_admin: Address,
        doc_hash: String,
        status: DocumentStatus,
        score: u32,
        comment_hash: String,
    ) {
        sub_admin.require_auth();
        if !Self::is_sub_admin(&env, &sub_admin) {
            panic!("not authorized: only sub-admins can submit reviews");
        }
        let review = Review {
            reviewer: sub_admin.clone(),
            status,
            score,
            comment_hash,
            timestamp: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::DocumentReview(doc_hash, sub_admin), &review);
    }

    pub fn read_review(env: Env, doc_hash: String, reviewer: Address) -> Option<Review> {
        env.storage()
            .persistent()
            .get(&DataKey::DocumentReview(doc_hash, reviewer))
    }

    // ---- Multi-sig governance ----

    pub fn create_proposal(env: Env, proposer: Address, action: ProposalAction) -> u64 {
        proposer.require_auth();
        let main_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MainAdmin)
            .expect("contract not initialized");
        if proposer != main_admin && !Self::is_sub_admin(&env, &proposer) {
            panic!("only main admin or sub-admin can create proposals");
        }

        let mut count: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::ProposalCount)
            .unwrap_or(0);
        count += 1;

        let approvals: Vec<Address> = Vec::new(&env);
        let proposal = Proposal {
            id: count,
            action,
            approvals,
            executed: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::ProposalCount, &count);
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(count), &proposal);
        count
    }

    pub fn approve_proposal(env: Env, sub_admin: Address, proposal_id: u64) {
        sub_admin.require_auth();
        if !Self::is_sub_admin(&env, &sub_admin) {
            panic!("only sub-admins can approve proposals");
        }

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal not found");

        if proposal.executed {
            panic!("proposal already executed");
        }

        // Guard against double-approval
        let mut already = false;
        for existing in proposal.approvals.iter() {
            if existing == sub_admin {
                already = true;
                break;
            }
        }
        if already {
            panic!("already approved by this sub-admin");
        }

        proposal.approvals.push_back(sub_admin);

        // Auto-execute if threshold is met
        let threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::GovernanceThreshold)
            .unwrap_or(1);
        if (proposal.approvals.len() as u32) >= threshold {
            Self::execute_action(&env, &proposal.action);
            proposal.executed = true;
        }

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
    }

    pub fn read_proposal(env: Env, proposal_id: u64) -> Option<Proposal> {
        env.storage().persistent().get(&DataKey::Proposal(proposal_id))
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{Address, Env, String};

    // ---- helpers ----

    fn setup(env: &Env) -> (Address, Address) {
        let main_admin: Address = Address::generate(env);
        let contract_addr: Address = env.register(Contract, ());
        let client = ContractClient::new(env, &contract_addr);
        client.init(&main_admin);
        env.ledger().with_mut(|li| {
            li.timestamp = 1_800_000_000;
            li.sequence_number += 1;
        });
        (main_admin, contract_addr)
    }

    fn make_hash(env: &Env, suffix: &str) -> String {
        String::from_str(
            env,
            &format!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{}",
                suffix
            ),
        )
    }

    // =======================================================================
    // Existing tests (updated for renamed DataKey / methods)
    // =======================================================================

    #[test]
    #[should_panic]
    fn only_owner_can_store_panics_without_auth() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);

        let name = String::from_str(&env, "Confidential.pdf");
        let hash = String::from_str(&env, "abc123");

        client.store_document(&admin, &name, &hash);
    }

    #[test]
    fn store_and_verify_document_with_owner_auth() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "OfferLetter.pdf");
        let hash = String::from_str(
            &env,
            "2d8f1bd06c6f0c2c2f2b2b4a7b3a9b2e4a5b8d6f9e0c1d3f4a6b7c8d9e0f1a2b",
        );

        client.store_document(&admin, &name, &hash);

        let stored = client.read_document(&hash).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.added_by, admin);
        assert!(stored.timestamp > 0);
        assert_eq!(stored.status, CertificateStatus::Submitted);
        assert_eq!(stored.expiry, 0u64);

        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.name, name);
        assert_eq!(verified.hash, hash);
        assert_eq!(verified.added_by, admin);
        assert!(verified.timestamp > 0);
        assert_eq!(verified.certificate_status, CertificateStatus::Submitted);
        assert_eq!(verified.expiry, 0u64);
        assert!(!verified.verified_document);
    }

    #[test]
    fn store_and_verify_multiple_documents_with_owner_auth() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "OfferLetter.pdf");
        let hash = String::from_str(
            &env,
            "2d8f1bd06c6f0c2c2f2b2b4a7b3a9b2e4a5b8d6f9e0c1d3f4a6b7c8d9e0f1a2b",
        );
        let hash1 = String::from_str(
            &env,
            "3d8f1bd06c6f0c2c2f2b2b4a7b3a9b2e4a5b8d6f9e0c1d3f4a6b7c8d9e0f1a2b",
        );

        client.store_document(&admin, &name, &hash);
        client.store_document(&admin, &name, &hash1);

        let stored = client.read_document(&hash).expect("document should exist");
        let stored1 = client.read_document(&hash1).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored1.hash, hash1);
    }

    #[test]
    fn whitelist_add_two_and_remove_one_with_owner_auth() {
        let env = Env::default();
        let (_admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);

        client.whitelist_address(&a1);
        client.whitelist_address(&a2);

        assert!(client.is_whitelisted(&a1), "a1 should be whitelisted");
        assert!(client.is_whitelisted(&a2), "a2 should be whitelisted");

        client.remove_from_whitelist(&a1);
        assert!(
            !client.is_whitelisted(&a1),
            "a1 should NOT be whitelisted anymore"
        );
        assert!(client.is_whitelisted(&a2), "a2 should remain whitelisted");
    }

    #[test]
    fn store_document_by_whitelisted_user() {
        let env = Env::default();
        let (_admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let user = Address::generate(&env);
        client.whitelist_address(&user);

        let name = String::from_str(&env, "Whitelisted-Doc.pdf");
        let hash = make_hash(&env, "aa");

        client.store_document(&user, &name, &hash);

        let stored = client.read_document(&hash).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.added_by, user, "added_by must be the whitelisted caller");
        assert!(stored.timestamp > 0);
        assert_eq!(stored.status, CertificateStatus::Submitted);
        assert_eq!(stored.expiry, 0u64);
    }

    #[test]
    #[should_panic(expected = "not authorized: only main admin or whitelisted address")]
    fn store_document_by_non_whitelisted_user_panics() {
        let env = Env::default();
        let (_admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let user = Address::generate(&env);

        let name = String::from_str(&env, "Not-Whitelisted-Doc.pdf");
        let hash = String::from_str(
            &env,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        client.store_document(&user, &name, &hash);
    }

    #[test]
    #[should_panic(expected = "Document already registered")]
    fn store_document_duplicate_hash_panics() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name1 = String::from_str(&env, "Doc-v1.pdf");
        let name2 = String::from_str(&env, "Doc-v2.pdf");
        let hash = String::from_str(
            &env,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );

        client.store_document(&admin, &name1, &hash);
        client.store_document(&admin, &name2, &hash);
    }

    #[test]
    fn reads_main_admin_address() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        let got = client.main_admin_address();
        assert_eq!(got, admin);
    }

    #[test]
    fn transfer_main_admin_with_auth() {
        let env = Env::default();
        let (_admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let new_admin = Address::generate(&env);
        client.transfer_main_admin(&new_admin);

        let got = client.main_admin_address();
        assert_eq!(got, new_admin, "main admin should be transferred");
    }

    #[test]
    #[should_panic]
    fn transfer_main_admin_without_auth_panics() {
        let env = Env::default();
        let (_admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        let new_admin = Address::generate(&env);
        client.transfer_main_admin(&new_admin);
    }

    // =======================================================================
    // Sub-admin management tests
    // =======================================================================

    #[test]
    fn test_add_and_remove_sub_admin() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let sub1 = Address::generate(&env);
        let sub2 = Address::generate(&env);

        // Add two sub-admins
        client.add_sub_admin(&admin, &sub1);
        client.add_sub_admin(&admin, &sub2);

        assert!(client.is_sub_admin_public(&sub1));
        assert!(client.is_sub_admin_public(&sub2));

        // Remove sub1
        client.remove_sub_admin(&admin, &sub1);
        assert!(!client.is_sub_admin_public(&sub1));
        assert!(client.is_sub_admin_public(&sub2));
    }

    // =======================================================================
    // Compliance review tests
    // =======================================================================

    #[test]
    fn test_submit_compliance_review() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Whitelist a user to upload a document
        let uploader = Address::generate(&env);
        client.whitelist_address(&uploader);

        // Upload a document
        let name = String::from_str(&env, "Report-Q1.pdf");
        let hash = make_hash(&env, "report");
        client.store_document(&uploader, &name, &hash);

        // Add a sub-admin
        let reviewer = Address::generate(&env);
        client.add_sub_admin(&admin, &reviewer);

        // Sub-admin submits a review
        let status = DocumentStatus::ApprovedWithRecommendations;
        let score: u32 = 85;
        let comment_hash = String::from_str(&env, "QmCommentIPFSHash123");
        client.submit_review(&reviewer, &hash, &status, &score, &comment_hash);

        // Read it back and assert
        let stored = client
            .read_review(&hash, &reviewer)
            .expect("review should exist");
        assert_eq!(stored.reviewer, reviewer);
        assert_eq!(stored.status, DocumentStatus::ApprovedWithRecommendations);
        assert_eq!(stored.score, 85);
        assert_eq!(stored.comment_hash, comment_hash);
        assert!(stored.timestamp > 0);
    }

    // =======================================================================
    // Multi-sig governance tests
    // =======================================================================

    #[test]
    fn test_multisig_governance_success() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Set threshold to 2
        client.set_threshold(&admin, &2u32);

        // Add two sub-admins
        let sub1 = Address::generate(&env);
        let sub2 = Address::generate(&env);
        client.add_sub_admin(&admin, &sub1);
        client.add_sub_admin(&admin, &sub2);

        // Whitelisted user uploads a document
        let uploader = Address::generate(&env);
        client.whitelist_address(&uploader);

        let doc_name = String::from_str(&env, "Certificate.pdf");
        let doc_hash = make_hash(&env, "cert");
        client.store_document(&uploader, &doc_name, &doc_hash);

        // Verify document exists
        assert!(client.read_document(&doc_hash).is_some());

        // Create a RevokeCertificate proposal (as sub1)
        let action = ProposalAction::RevokeCertificate(doc_hash.clone());
        let proposal_id = client.create_proposal(&sub1, &action);
        assert_eq!(proposal_id, 1);

        // sub1 approves — threshold not yet met
        client.approve_proposal(&sub1, &proposal_id);

        // Proposal should NOT be executed yet (only 1/2 approvals)
        let prop = client
            .read_proposal(&proposal_id)
            .expect("proposal should exist");
        assert_eq!(prop.approvals.len(), 1);
        assert!(!prop.executed);
        // Document should still exist
        assert!(client.read_document(&doc_hash).is_some());

        // sub2 approves — threshold met, auto-executes
        client.approve_proposal(&sub2, &proposal_id);

        // Proposal should be executed
        let executed_prop = client
            .read_proposal(&proposal_id)
            .expect("proposal should still exist");
        assert!(executed_prop.executed);
        // Document should be marked Revoked (not deleted)
        let revoked_doc = client.read_document(&doc_hash).expect("document should still exist");
        assert_eq!(revoked_doc.status, CertificateStatus::Revoked);
    }

    #[test]
    fn test_multisig_governance_threshold_not_met() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Set threshold to 2
        client.set_threshold(&admin, &2u32);

        // Add only ONE sub-admin
        let sub1 = Address::generate(&env);
        client.add_sub_admin(&admin, &sub1);

        // Upload a document
        let uploader = Address::generate(&env);
        client.whitelist_address(&uploader);
        let doc_name = String::from_str(&env, "Doc.pdf");
        let doc_hash = make_hash(&env, "doc");
        client.store_document(&uploader, &doc_name, &doc_hash);

        // Create a RevokeCertificate proposal
        let action = ProposalAction::RevokeCertificate(doc_hash.clone());
        let proposal_id = client.create_proposal(&sub1, &action);

        // Only one approval — threshold is 2, should NOT auto-execute
        client.approve_proposal(&sub1, &proposal_id);

        let prop = client
            .read_proposal(&proposal_id)
            .expect("proposal should exist");
        assert_eq!(prop.approvals.len(), 1);
        assert!(!prop.executed);
        // Document should still exist
        assert!(client.read_document(&doc_hash).is_some());
    }

    #[test]
    fn test_multisig_update_threshold_proposal() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let sub = Address::generate(&env);
        client.add_sub_admin(&admin, &sub);

        // Propose threshold change from 1 to 3
        // Default threshold is 1, so this will auto-execute on first approval
        let action = ProposalAction::UpdateThreshold(3);
        let pid = client.create_proposal(&admin, &action);
        client.approve_proposal(&sub, &pid);

        let new_threshold = client.governance_threshold();
        assert_eq!(new_threshold, 3);

        let prop = client.read_proposal(&pid).expect("proposal should exist");
        assert!(prop.executed);
    }

    // =======================================================================
    // Certificate lifecycle tests
    // =======================================================================

    #[test]
    fn test_issue_certificate_success() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "Cert-Doc.pdf");
        let hash = make_hash(&env, "certdoc");
        client.store_document(&admin, &name, &hash);

        // Issue certificate with expiry
        let expiry = 2_000_000_000u64;
        client.issue_certificate(&admin, &hash, &expiry);

        let doc = client.read_document(&hash).expect("document should exist");
        assert_eq!(doc.status, CertificateStatus::Issued);
        assert_eq!(doc.expiry, expiry);

        // Verify returns Issued + verified
        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.certificate_status, CertificateStatus::Issued);
        assert!(verified.verified_document);
        assert_eq!(verified.expiry, expiry);
    }

    #[test]
    #[should_panic(expected = "only main admin can issue certificates")]
    fn test_issue_certificate_not_authorized() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "Doc.pdf");
        let hash = make_hash(&env, "doc");
        client.store_document(&admin, &name, &hash);

        // Non-admin tries to issue
        let imposter = Address::generate(&env);
        client.issue_certificate(&imposter, &hash, &1_000_000u64);
    }

    #[test]
    #[should_panic(expected = "certificate can only be issued from Submitted status")]
    fn test_issue_certificate_already_issued() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "Doc.pdf");
        let hash = make_hash(&env, "doc");
        client.store_document(&admin, &name, &hash);

        client.issue_certificate(&admin, &hash, &2_000_000_000u64);
        // Second issue should panic
        client.issue_certificate(&admin, &hash, &3_000_000_000u64);
    }

    #[test]
    fn test_verify_submitted_certificate() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "Doc.pdf");
        let hash = make_hash(&env, "doc");
        client.store_document(&admin, &name, &hash);

        // Before issuing, verify should return Submitted + not verified
        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.certificate_status, CertificateStatus::Submitted);
        assert!(!verified.verified_document);
        assert_eq!(verified.expiry, 0u64);
    }

    #[test]
    fn test_verify_expired_certificate() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Set ledger to a known timestamp
        let current_time = 1_800_000_000u64;
        env.ledger().with_mut(|li| {
            li.timestamp = current_time;
        });

        let name = String::from_str(&env, "Doc.pdf");
        let hash = make_hash(&env, "doc");
        client.store_document(&admin, &name, &hash);

        // Issue with expiry that's already passed
        let past_expiry = current_time - 100;
        client.issue_certificate(&admin, &hash, &past_expiry);

        // Verify returns Expired + not verified
        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.certificate_status, CertificateStatus::Expired);
        assert!(!verified.verified_document);
        assert_eq!(verified.expiry, past_expiry);
    }

    #[test]
    fn test_verify_revoked_certificate() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Set threshold to 1 so a single sub-admin can execute
        client.set_threshold(&admin, &1u32);

        let sub = Address::generate(&env);
        client.add_sub_admin(&admin, &sub);

        let name = String::from_str(&env, "Doc.pdf");
        let hash = make_hash(&env, "doc");
        client.store_document(&admin, &name, &hash);

        // Issue certificate
        let expiry = 2_000_000_000u64;
        client.issue_certificate(&admin, &hash, &expiry);

        // Confirm Issued
        assert_eq!(
            client.read_document(&hash).unwrap().status,
            CertificateStatus::Issued
        );

        // Revoke via governance proposal
        let action = ProposalAction::RevokeCertificate(hash.clone());
        let pid = client.create_proposal(&sub, &action);
        client.approve_proposal(&sub, &pid);

        // Document should be Revoked
        let doc = client.read_document(&hash).unwrap();
        assert_eq!(doc.status, CertificateStatus::Revoked);

        // Verify returns Revoked + not verified
        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.certificate_status, CertificateStatus::Revoked);
        assert!(!verified.verified_document);
    }

    #[test]
    fn test_contract_upgrade() {
        let env = Env::default();
        let (admin, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // Set threshold to 2 so 1 approval doesn't auto-execute
        client.set_threshold(&admin, &2u32);

        let sub = Address::generate(&env);
        client.add_sub_admin(&admin, &sub);

        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);
        let action = ProposalAction::ContractUpgrade(wasm_hash.clone());
        let pid = client.create_proposal(&admin, &action);
        assert_eq!(pid, 1);

        // Verify proposal was created with correct action
        let prop = client.read_proposal(&pid).expect("proposal should exist");
        assert!(!prop.executed);
        match &prop.action {
            ProposalAction::ContractUpgrade(h) => {
                assert_eq!(h, &wasm_hash);
            }
            _ => panic!("expected ContractUpgrade action"),
        }

        // Approve once — threshold is 2, so not executed yet
        client.approve_proposal(&sub, &pid);
        let after_one = client.read_proposal(&pid).unwrap();
        assert_eq!(after_one.approvals.len(), 1);
        assert!(!after_one.executed);
    }

    // =======================================================================
    // End-to-end integration test — full flow
    // =======================================================================

    /// Simulates hashing a document: returns a deterministic hex string.
    fn doc_hash(env: &Env, name: &str) -> String {
        let raw = format!("e2e{:0>62}", name.chars().fold(0u64, |acc, c| acc.wrapping_add(c as u64)));
        String::from_str(env, &raw[..64])
    }

    #[test]
    fn test_e2e_full_flow() {
        let env = Env::default();
        let (admin, contract_id) = setup(&env);
        let client = ContractClient::new(&env, &contract_id);

        env.mock_all_auths();

        // Setup
        assert!(client.main_admin_address() == admin);

        let company_user_1 = Address::generate(&env);
        let company_user_2 = Address::generate(&env);
        client.whitelist_address(&company_user_1);
        client.whitelist_address(&company_user_2);
        assert!(client.is_whitelisted(&company_user_1));
        assert!(client.is_whitelisted(&company_user_2));

        let sub_a = Address::generate(&env);
        let sub_b = Address::generate(&env);
        let sub_c = Address::generate(&env);
        client.add_sub_admin(&admin, &sub_a);
        client.add_sub_admin(&admin, &sub_b);
        client.add_sub_admin(&admin, &sub_c);
        assert!(client.is_sub_admin_public(&sub_a));
        assert!(client.is_sub_admin_public(&sub_b));
        assert!(client.is_sub_admin_public(&sub_c));

        client.set_threshold(&admin, &2u32);
        assert_eq!(client.governance_threshold(), 2);

        // Store doc
        let doc_name = String::from_str(&env, "Q4-Audit-Report.pdf");
        let doc_hash_val = doc_hash(&env, "Q4-Audit-Report.pdf");
        client.store_document(&company_user_1, &doc_name, &doc_hash_val);
        let stored = client.read_document(&doc_hash_val).expect("document should exist");
        assert_eq!(stored.name, doc_name);
        assert_eq!(stored.hash, doc_hash_val);
        assert_eq!(stored.added_by, company_user_1);
        assert_eq!(stored.status, CertificateStatus::Submitted);
        assert_eq!(stored.expiry, 0u64);

        // Verify document before issuing — should be Submitted and not verified
        let pre_issue = client.verify_document(&doc_hash_val).expect("should verify");
        assert_eq!(pre_issue.certificate_status, CertificateStatus::Submitted);
        assert!(!pre_issue.verified_document);

        // Reviews
        client.submit_review(
            &sub_a, &doc_hash_val, &DocumentStatus::ApprovedWithRecommendations,
            &85u32, &String::from_str(&env, "ipfs://QmCommentA"),
        );
        client.submit_review(
            &sub_b, &doc_hash_val, &DocumentStatus::Approved,
            &92u32, &String::from_str(&env, "ipfs://QmCommentB"),
        );

        let review_a = client.read_review(&doc_hash_val, &sub_a).expect("review should exist");
        assert_eq!(review_a.reviewer, sub_a);
        assert_eq!(review_a.status, DocumentStatus::ApprovedWithRecommendations);
        assert_eq!(review_a.score, 85);

        let review_b = client.read_review(&doc_hash_val, &sub_b).expect("review should exist");
        assert_eq!(review_b.reviewer, sub_b);
        assert_eq!(review_b.status, DocumentStatus::Approved);
        assert_eq!(review_b.score, 92);

        // Issue certificate (admin only) with expiry far in the future
        let expiry = 1_900_000_000u64;
        client.issue_certificate(&admin, &doc_hash_val, &expiry);
        let issued_doc = client.read_document(&doc_hash_val).expect("document should exist");
        assert_eq!(issued_doc.status, CertificateStatus::Issued);
        assert_eq!(issued_doc.expiry, expiry);

        // Verify document after issuing — should be Issued and verified
        let verified = client.verify_document(&doc_hash_val).expect("should verify");
        assert_eq!(verified.certificate_status, CertificateStatus::Issued);
        assert!(verified.verified_document);
        assert_eq!(verified.expiry, expiry);

        // Scenario A — RevokeCertificate via multi-sig DAO
        let revoke_action = ProposalAction::RevokeCertificate(doc_hash_val.clone());
        let prop_id_1 = client.create_proposal(&sub_a, &revoke_action);
        assert_eq!(prop_id_1, 1);

        // sub_a approves — only 1/2, NOT executed
        client.approve_proposal(&sub_a, &prop_id_1);
        let p1_before = client.read_proposal(&prop_id_1).unwrap();
        assert_eq!(p1_before.approvals.len(), 1);
        assert!(!p1_before.executed);
        // Doc still Issued (proposal not executed yet)
        let still_issued = client.read_document(&doc_hash_val).unwrap();
        assert_eq!(still_issued.status, CertificateStatus::Issued);

        // sub_b approves — 2/2 => auto-executes, doc marked Revoked
        client.approve_proposal(&sub_b, &prop_id_1);
        let p1_done = client.read_proposal(&prop_id_1).unwrap();
        assert!(p1_done.executed);
        // Document still exists but is Revoked
        let revoked_doc = client.read_document(&doc_hash_val).expect("doc should still exist");
        assert_eq!(revoked_doc.status, CertificateStatus::Revoked);
        // Verify returns Revoked, not verified
        let revoked_verify = client.verify_document(&doc_hash_val).expect("should verify");
        assert_eq!(revoked_verify.certificate_status, CertificateStatus::Revoked);
        assert!(!revoked_verify.verified_document);

        // Scenario B — UpdateThreshold via multi-sig DAO
        let update_action = ProposalAction::UpdateThreshold(5u32);
        let prop_id_2 = client.create_proposal(&sub_b, &update_action);
        assert_eq!(prop_id_2, 2);

        // sub_c approves — only 1/2
        client.approve_proposal(&sub_c, &prop_id_2);
        let p2_before = client.read_proposal(&prop_id_2).unwrap();
        assert!(!p2_before.executed);

        // sub_a approves — 2/2 => auto-executes
        client.approve_proposal(&sub_a, &prop_id_2);
        assert_eq!(client.governance_threshold(), 5);
        let p2_done = client.read_proposal(&prop_id_2).unwrap();
        assert!(p2_done.executed);

        // Scenario C — threshold not met, should NOT execute
        client.set_threshold(&admin, &2u32);
        let doc_2 = String::from_str(&env, "Audit-Summary.pdf");
        let hash_2 = doc_hash(&env, "Audit-Summary.pdf");
        client.store_document(&company_user_2, &doc_2, &hash_2);

        let revoke_2 = ProposalAction::RevokeCertificate(hash_2.clone());
        let prop_id_3 = client.create_proposal(&sub_a, &revoke_2);
        assert_eq!(prop_id_3, 3);

        // Only sub_a approves (1 approval), threshold is 2
        client.approve_proposal(&sub_a, &prop_id_3);
        let p3 = client.read_proposal(&prop_id_3).unwrap();
        assert!(!p3.executed);
        // Document should still exist (not revoked)
        assert!(client.read_document(&hash_2).is_some());

        // Cleanup
        client.remove_sub_admin(&admin, &sub_c);
        assert!(!client.is_sub_admin_public(&sub_c));
        assert!(client.is_sub_admin_public(&sub_a));
        assert!(client.is_sub_admin_public(&sub_b));
    }
}
