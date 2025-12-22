module merkle_airdrop::airdrop {

    use std::bcs::to_bytes;
    use std::hash;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::table;
    use aptos_std::table::Table;

    /// Errors
    const E_NOT_ELIGIBLE: u64 = 1;
    const E_ALREADY_CLAIMED: u64 = 2;
    const E_NOT_ADMIN: u64 = 3;

    /// Admin address
    const ADMIN: address = @merkle_airdrop;

    // Globle Config
    struct Config has key {
        merkel_root: vector<u8>,
        claimed: Table<address, bool>
    }

    /// Initialize contract
    public entry fun init(admin: &signer, root: vector<u8>){
        assert!(address_of(admin) == ADMIN, E_NOT_ADMIN);

        let claimed  = table::new<address,bool>();
        move_to(admin, Config {
            merkel_root: root,
            claimed
        });
    }

    /// Claim airdrop
    public entry fun cliam(
        user: &signer,
        amount: u64,
        proof: vector<vector<u8>>,
        positions: vector<bool> // true == sibling is left
    ) acquires Config {
        let user_addr = address_of(user);
        let config = borrow_global_mut<Config>(ADMIN);

        // Prevent double cliam
        assert!(!table::contains(&config.claimed, user_addr), E_ALREADY_CLAIMED);

        let leaf = compute_leaf(user_addr, amount);

        let valid = verify_proof(
            leaf,
            proof,
            positions,
            &config.merkel_root
        );

        assert!(valid, E_NOT_ELIGIBLE);

        // Mark Claimed
        table::add(&mut config.claimed, user_addr, true);

        // Tranfer supra
    }

    /// Compute leaf
    fun compute_leaf(addr: address, amount: u64): vector<u8> {
        let bytes = vector::empty<u8>();
        vector::append(&mut bytes, to_bytes(&addr));
        vector::append(&mut bytes, u64_to_bytes(amount));
        hash::sha3_256(bytes)
    }

    /// Convert u64 to bytes
    fun u64_to_bytes(value: u64): vector<u8> {
        let bytes = vector::empty<u8>();
        let i = 0;

        while (i < 8) {
            vector::push_back(&mut bytes, (((value >> ((7 - i) * 8)) & 0xff) as u8));
            i = i + 1;
        };
        bytes
    }

    /// Verify Merkle proof
    fun verify_proof(
        leaf: vector<u8>,
        proof: vector<vector<u8>>,
        positions: vector<bool>,
        root: &vector<u8>
    ): bool {
        let computed = leaf;
        let len = vector::length(&proof);
        let i = 0;

        while(i < len) {
            let sibling = *vector::borrow(&proof, i);
            let is_left = *vector::borrow(&mut positions, i);

            let combined = vector::empty<u8>();

            if(is_left){
                vector::append(&mut combined, sibling);
                vector::append(&mut combined, computed);
            }else{
                vector::append(&mut combined, computed);
                vector::append(&mut combined, sibling);
            };

            computed = hash::sha3_256(combined);
            i = i + 1 ;
        };
        computed == *root
    }

    #[test_only]
    public fun is_claimed(addr: address): bool acquires Config {
        let config = borrow_global<Config>(ADMIN);
        table::contains(&config.claimed, addr)
    }

}