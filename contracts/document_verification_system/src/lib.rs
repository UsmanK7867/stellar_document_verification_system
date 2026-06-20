#![cfg_attr(not(test), no_std)]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contract]
pub struct Contract;

#[derive(Clone)]
#[contracttype]
enum DataKey {
    /// Instance-scoped owner (no rent burden like maps of docs)
    Owner,
    /// Persistent map: Document keyed by its hash string
    Document(String),
    /// Persistent map: Whitelist keyed by Address (value = bool)
    Whitelist(Address),
}

/// Stored document data
#[derive(Clone)]
#[contracttype]
pub struct Document {
    pub name: String,
    pub hash: String,
    pub timestamp: u64,
    pub added_by: Address,
}

/// Result used by verify_document (adds a boolean flag)
#[derive(Clone)]
#[contracttype]
pub struct VerifiedDocument {
    pub name: String,
    pub hash: String,
    pub timestamp: u64,
    pub added_by: Address,
    pub verified_document: bool,
}

#[contractimpl]
impl Contract {
    /// Initialize the contract with an owner. Must be called once right after deployment.
    pub fn init(env: Env, owner: Address) {
        if env.storage().instance().has(&DataKey::Owner) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Owner, &owner);
    }

    /// Internal: fetch owner, ensure they authorized this call
    fn assert_owner(env: &Env) -> Address {
        let owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::Owner)
            .expect("contract not initialized");
        owner.require_auth();
        owner
    }
   /// Require that `actor` is the owner OR is whitelisted; otherwise panic.
fn assert_owner_or_whitelisted_actor(env: &Env, actor: &Address) {
    // Must have signed
    actor.require_auth();

    // Load owner
    let owner: Address = env
        .storage()
        .instance()
        .get(&DataKey::Owner)
        .expect("contract not initialized");

    // Owner always allowed
    if actor == &owner {
        return;
    }

    // Otherwise must be whitelisted
    let allowed = env
        .storage()
        .persistent()
        .get::<_, bool>(&DataKey::Whitelist(actor.clone()))
        .unwrap_or(false);

    if !allowed {
        panic!("not authorized: only owner or whitelisted address");
    }
}



    // ---------- WHITELIST ----------

    /// Owner-only: add address to whitelist (value stored as `true`)
    pub fn whitelist_address(env: Env, address: Address) {
        let _owner = Self::assert_owner(&env);
        let allow = true;
        env.storage()
            .persistent()
            .set(&DataKey::Whitelist(address), &allow);
    }

    /// Read-only: check if address is whitelisted (missing => false)
    pub fn is_whitelisted(env: Env, address: Address) -> bool {
        env.storage()
            .persistent()
            .get::<_, bool>(&DataKey::Whitelist(address))
            .unwrap_or(false)
    }
   pub fn owner_address(env: Env) -> Address {
    env.storage()
        .instance()
        .get::<_, Address>(&DataKey::Owner)
        .expect("contract not initialized")
}

    /// Owner-only: remove address from whitelist (delete key)
    pub fn remove_from_whitelist(env: Env, address: Address) {
        let _owner = Self::assert_owner(&env);
        env.storage().persistent().remove(&DataKey::Whitelist(address));
    }

    // ---------- DOCUMENTS ----------

    /// Store a document (ONLY OWNER and whitelist).
    pub fn store_document(env: Env, actor: Address, name: String, hash: String) {

          let key = DataKey::Document(hash.clone());

        if env.storage().persistent().has(&key) {
            panic!("Document already registered");
        }

    // Enforce permission
    Self::assert_owner_or_whitelisted_actor(&env, &actor);
        let timestamp: u64 = env.ledger().timestamp();
        let doc = Document {
            name,
            hash: hash.clone(),
            timestamp,
            added_by: actor,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Document(hash), &doc);
    }

    /// Read a document by hash (helper; anyone can call).
    pub fn read_document(env: Env, hash: String) -> Option<Document> {
        env.storage().persistent().get(&DataKey::Document(hash))
    }

    /// Verify a document by its hash.
    pub fn verify_document(env: Env, hash: String) -> Option<VerifiedDocument> {
        let doc: Option<Document> = env.storage().persistent().get(&DataKey::Document(hash));
        doc.map(|d| VerifiedDocument {
            name: d.name,
            hash: d.hash,
            timestamp: d.timestamp,
            added_by: d.added_by,
            verified_document: true,
        })
    }
    // transfer Ownership
    pub fn transfer_ownership(env: Env, new_owner: Address) {
    // Ensure the *current* owner authorized this call
    let current_owner: Address = env
        .storage()
        .instance()
        .get(&DataKey::Owner)
        .expect("contract not initialized");
    current_owner.require_auth();

    // Optional: prevent no-op/self-transfer
    if new_owner == current_owner {
        panic!("new owner must be different");
    }

    env.storage().instance().set(&DataKey::Owner, &new_owner);
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Address, Env, String};
    use soroban_sdk::testutils::{Address as _, Ledger}; // trait import

    fn setup(env: &Env) -> (Address, Address) {
        let owner: Address = Address::generate(env);
        let contract_addr: Address = env.register_contract(None, Contract);
        let client = ContractClient::new(env, &contract_addr);
        client.init(&owner);
        env.ledger().with_mut(|li| {
            li.timestamp = 1_800_000_000;
            li.sequence_number += 1;
        });
        (owner, contract_addr)
    }

    #[test]
    #[should_panic] // require_auth should fail without mocked auth
    fn only_owner_can_store_panics_without_auth() {
        let env = Env::default();
        let (owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);

        let name = String::from_str(&env, "Confidential.pdf");
        let hash = String::from_str(&env, "abc123");

        // Now requires the actor argument; without mock auth this should panic.
        client.store_document(&owner, &name, &hash);
    }

    #[test]
    fn store_and_verify_document_with_owner_auth() {
        let env = Env::default();
        let (owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        let name = String::from_str(&env, "OfferLetter.pdf");
        let hash = String::from_str(
            &env,
            "2d8f1bd06c6f0c2c2f2b2b4a7b3a9b2e4a5b8d6f9e0c1d3f4a6b7c8d9e0f1a2b",
        );

        // pass owner as the authorized actor
        client.store_document(&owner, &name, &hash);

        let stored = client.read_document(&hash).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.added_by, owner);
        assert!(stored.timestamp > 0);

        let verified = client.verify_document(&hash).expect("should verify");
        assert_eq!(verified.name, name);
        assert_eq!(verified.hash, hash);
        assert_eq!(verified.added_by, owner);
        assert!(verified.timestamp > 0);
        assert!(verified.verified_document);
    }

    #[test]
    fn store_and_verify_multiple_documents_with_owner_auth() {
        let env = Env::default();
        let (owner, contract_addr) = setup(&env);
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

        // actor is required; use owner so no whitelist setup needed
        client.store_document(&owner, &name, &hash);
        client.store_document(&owner, &name, &hash1);

        let stored = client.read_document(&hash).expect("document should exist");
        let stored1 = client.read_document(&hash1).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored1.hash, hash1);
    }

    #[test]
    fn whitelist_add_two_and_remove_one_with_owner_auth() {
        let env = Env::default();
        let (_owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        // Allow require_auth to pass in tests
        env.mock_all_auths();

        // two random addresses
        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);

        // add both to whitelist (owner-only method; mock_all_auths lets it pass)
        client.whitelist_address(&a1);
        client.whitelist_address(&a2);

        // check both are whitelisted
        assert!(client.is_whitelisted(&a1), "a1 should be whitelisted");
        assert!(client.is_whitelisted(&a2), "a2 should be whitelisted");

        // remove one (a1) and check states
        client.remove_from_whitelist(&a1);
        assert!(!client.is_whitelisted(&a1), "a1 should NOT be whitelisted anymore");
        assert!(client.is_whitelisted(&a2), "a2 should remain whitelisted");
    }
     #[test]
    fn store_document_by_whitelisted_user() {
        let env = Env::default();
        let (owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths();

        // create & whitelist a non-owner user
        let user = Address::generate(&env);
        client.whitelist_address(&user);

        let name = String::from_str(&env, "Whitelisted-Doc.pdf");
        let hash = String::from_str(
            &env,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        // should succeed because `user` is whitelisted
        client.store_document(&user, &name, &hash);

        let stored = client.read_document(&hash).expect("document should exist");
        assert_eq!(stored.name, name);
        assert_eq!(stored.hash, hash);
        assert_eq!(stored.added_by, user, "added_by must be the whitelisted caller");
        assert!(stored.timestamp > 0);
    }

    #[test]
    #[should_panic(expected = "not authorized: only owner or whitelisted address")]
    fn store_document_by_non_whitelisted_user_panics() {
        let env = Env::default();
        let (_owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);
        env.mock_all_auths(); // make require_auth() pass so we fail specifically on whitelist

        // random user NOT added to whitelist
        let user = Address::generate(&env);

        let name = String::from_str(&env, "Not-Whitelisted-Doc.pdf");
        let hash = String::from_str(
            &env,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        // should panic because user is neither owner nor whitelisted
        client.store_document(&user, &name, &hash);
    }

#[test]
#[should_panic(expected = "Document already registered")]
fn store_document_duplicate_hash_panics() {
    let env = Env::default();
    let (owner, contract_addr) = setup(&env);
    let client = ContractClient::new(&env, &contract_addr);
    env.mock_all_auths();

    let name1 = String::from_str(&env, "Doc-v1.pdf");
    let name2 = String::from_str(&env, "Doc-v2.pdf");
    let hash = String::from_str(
        &env,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );

    // First insert succeeds
    client.store_document(&owner, &name1, &hash);

    // Second insert with same hash MUST panic
    client.store_document(&owner, &name2, &hash);
}

    #[test]
fn reads_owner_address() {
    let env = Env::default();
    let (owner, contract_addr) = setup(&env);
    let client = ContractClient::new(&env, &contract_addr);
    let got = client.owner_address();
    assert_eq!(got, owner);
}
    #[test]
    fn transfer_ownership_with_owner_auth() {
        let env = Env::default();
        let (owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);

        // allow require_auth to pass for the owner
        env.mock_all_auths();

        // transfer to a new owner address
        let new_owner = Address::generate(&env);
        client.transfer_ownership(&new_owner);

        // verify ownership changed
        // If you implemented `owner_address`, use that:
        let got = client.owner_address();
        assert_eq!(got, new_owner, "ownership should be transferred to new_owner");
    }

    #[test]
    #[should_panic] // should fail because owner did not authorize
    fn transfer_ownership_without_owner_auth_panics() {
        let env = Env::default();
        let (_owner, contract_addr) = setup(&env);
        let client = ContractClient::new(&env, &contract_addr);

        // DO NOT mock auth here so require_auth() fails
        let new_owner = Address::generate(&env);

        // This should panic: current owner didn't authorize this call
        client.transfer_ownership(&new_owner);
    }

}
 
