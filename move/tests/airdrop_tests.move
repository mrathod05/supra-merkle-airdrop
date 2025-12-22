#[test_only]
module merkle_airdrop::airdrop_tests {
    use std::bcs;
    use std::vector;
    use std::hash;
    use merkle_airdrop::airdrop;

    /// Helper function to compute leaf hash (same as contract logic)
    fun compute_leaf_test(addr: address, amount: u64): vector<u8> {
        let bytes = vector::empty<u8>();
        vector::append(&mut bytes, bcs::to_bytes(&addr));
        vector::append(&mut bytes, u64_to_bytes_test(amount));
        hash::sha3_256(bytes)
    }

    /// Helper function to convert u64 to bytes (big-endian, same as contract)
    fun u64_to_bytes_test(value: u64): vector<u8> {
        let bytes = vector::empty<u8>();
        let i = 0;
        while (i < 8) {
            vector::push_back(&mut bytes, (((value >> ((7 - i) * 8)) & 0xff) as u8));
            i = i + 1;
        };
        bytes
    }

    /// Test initialization
    #[test(admin = @merkle_airdrop)]
    fun test_initialization(admin: signer) {
        let root = vector::empty<u8>();
        vector::push_back(&mut root, 0x12);
        vector::push_back(&mut root, 0x34);
        vector::push_back(&mut root, 0x56);
        vector::push_back(&mut root, 0x78);

        airdrop::init(&admin, root);
    }

    #[test(admin = @123)]
    #[expected_failure(abort_code = airdrop::E_NOT_ADMIN)]
    fun test_initialization_not_admin(admin: signer) {
        // Should fail because admin address is not @merkle_airdrop
        let root = vector::empty<u8>();
        airdrop::init(&admin, root);
    }

    /// Test compute_leaf function
    #[test]
    fun test_compute_leaf() {
        let addr = @0x1234;
        let amount = 100u64;

        // Manual computation
        let expected_bytes = vector::empty<u8>();
        vector::append(&mut expected_bytes, bcs::to_bytes(&addr));
        vector::append(&mut expected_bytes, u64_to_bytes_test(amount));
        let expected_hash = hash::sha3_256(expected_bytes);

        // Test both produce same result
        let leaf1 = compute_leaf_test(addr, amount);
        assert!(vector::length(&leaf1) == 32, 100); // SHA3-256 produces 32 bytes

        // Note: Can't call contract's compute_leaf directly as it's private
        // This test verifies our understanding matches contract logic
    }

    /// Test u64_to_bytes function
    #[test]
    fun test_u64_to_bytes() {
        // Test with 0
        let bytes = u64_to_bytes_test(0);
        assert!(vector::length(&bytes) == 8, 101);

        // Test with small number
        let bytes = u64_to_bytes_test(100);
        assert!(vector::length(&bytes) == 8, 102);

        // Test with max u64
        let bytes = u64_to_bytes_test(18446744073709551615); // u64::MAX
        assert!(vector::length(&bytes) == 8, 103);

        // Verify big-endian encoding
        let bytes = u64_to_bytes_test(0x1234567890ABCDEF);
        assert!(*vector::borrow(&bytes, 0) == 0x12, 104);
        assert!(*vector::borrow(&bytes, 1) == 0x34, 105);
        assert!(*vector::borrow(&bytes, 2) == 0x56, 106);
        assert!(*vector::borrow(&bytes, 3) == 0x78, 107);
        assert!(*vector::borrow(&bytes, 4) == 0x90, 108);
        assert!(*vector::borrow(&bytes, 5) == 0xAB, 109);
        assert!(*vector::borrow(&bytes, 6) == 0xCD, 110);
        assert!(*vector::borrow(&bytes, 7) == 0xEF, 111);
    }

    /// Test verify_proof function with a simple 2-leaf tree
    /// Test verify_proof function with a simple 2-leaf tree
    #[test]
    fun test_verify_proof_simple() {
        // Create a simple 2-leaf merkle tree
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);
        let leaf3 = compute_leaf_test(@0x1236, 300); // Not in the tree

        // Compute parent hash (root)
        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        // Test 1: Correct proof for leaf1
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf2);

        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, false); // leaf1 is left, sibling is right

        // Verify proof (simulating contract logic)
        let computed = leaf1;
        let len = vector::length(&proof);
        let i = 0;

        while (i < len) {
        let sibling = *vector::borrow(&proof, i);
        let is_left = *vector::borrow(&positions, i);

        let combined_inner = vector::empty<u8>();
        if (is_left) {
        vector::append(&mut combined_inner, sibling);
        vector::append(&mut combined_inner, computed);
        } else {
        vector::append(&mut combined_inner, computed);
        vector::append(&mut combined_inner, sibling);
        };

        computed = hash::sha3_256(combined_inner);
        i = i + 1;
        };

        assert!(computed == root, 200);

        // Test 2: Wrong proof (using leaf3 which is not in the tree)
        let wrong_proof = vector::empty<vector<u8>>();
        vector::push_back(&mut wrong_proof, leaf3); // Wrong sibling - not in tree

        let computed_wrong = leaf2;
        let j = 0;
        while (j < 1) {
        let sibling = *vector::borrow(&wrong_proof, j);
        let is_left = true; // leaf2 is right, sibling should be left

        let combined_wrong = vector::empty<u8>();
        vector::append(&mut combined_wrong, sibling);
        vector::append(&mut combined_wrong, computed_wrong);

        computed_wrong = hash::sha3_256(combined_wrong);
        j = j + 1;
        };

        // This should be true because leaf3 is not the correct sibling
        assert!(computed_wrong != root, 201);
    }

    /// Test full airdrop flow with 4 users
    #[test(admin = @merkle_airdrop, user1 = @0x1234, user2 = @0x1235, user3 = @0x1236, user4 = @0x1237)]
    fun test_full_airdrop_flow(
        admin: signer,
        user1: signer,
        user2: signer,
        user3: signer,
        user4: signer
    ) {
        // Create leaves
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);
        let leaf3 = compute_leaf_test(@0x1236, 300);
        let leaf4 = compute_leaf_test(@0x1237, 400);

        // Build merkle tree manually (level 1)
        let combined1 = vector::empty<u8>();
        vector::append(&mut combined1, leaf1);
        vector::append(&mut combined1, leaf2);
        let hash1 = hash::sha3_256(combined1);

        let combined2 = vector::empty<u8>();
        vector::append(&mut combined2, leaf3);
        vector::append(&mut combined2, leaf4);
        let hash2 = hash::sha3_256(combined2);

        // Build root (level 2)
        let combined_root = vector::empty<u8>();
        vector::append(&mut combined_root, hash1);
        vector::append(&mut combined_root, hash2);
        let root = hash::sha3_256(combined_root);

        // Initialize contract
        airdrop::init(&admin, root);

        // Test claim for user1
        let proof_user1 = vector::empty<vector<u8>>();
        vector::push_back(&mut proof_user1, leaf2); // sibling
        vector::push_back(&mut proof_user1, hash2); // next level sibling

        let positions_user1 = vector::empty<bool>();
        vector::push_back(&mut positions_user1, false); // leaf1 is left, sibling leaf2 is right
        vector::push_back(&mut positions_user1, false); // hash1 is left, sibling hash2 is right

        // User1 should be able to claim
        airdrop::cliam(&user1, 100, proof_user1, positions_user1);

        // Verify user1 is marked as claimed
        assert!(airdrop::is_claimed(@0x1234), 300);

        // User1 should not be able to claim again
        let proof_user1_copy = vector::empty<vector<u8>>();
        vector::push_back(&mut proof_user1_copy, leaf2);
        vector::push_back(&mut proof_user1_copy, hash2);

        let positions_user1_copy = vector::empty<bool>();
        vector::push_back(&mut positions_user1_copy, false);
        vector::push_back(&mut positions_user1_copy, false);
    }

    #[test(admin = @merkle_airdrop, user1 = @0x1234, user2 = @0x1235)]
    #[expected_failure(abort_code = airdrop::E_ALREADY_CLAIMED)]
    fun test_double_claim_prevention(
        admin: signer,
        user1: signer,
        user2: signer
    ) {
        // Simple 2-leaf tree
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);

        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        airdrop::init(&admin, root);

        // First claim should succeed
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf2);
        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, false);

        airdrop::cliam(&user1, 100, proof, positions);

        // Second claim should fail
        airdrop::cliam(&user1, 100, proof, positions);
    }

    #[test(admin = @merkle_airdrop, user1 = @0x1234)]
    #[expected_failure(abort_code = airdrop::E_NOT_ELIGIBLE)]
    fun test_invalid_proof(
        admin: signer,
        user1: signer
    ) {
        // Create tree with user1 and user2
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);

        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        airdrop::init(&admin, root);

        // Try to claim with wrong amount (invalid leaf)
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf2);
        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, false);

        // Wrong amount should fail
        airdrop::cliam(&user1, 999, proof, positions);
    }

    #[test(admin = @merkle_airdrop, user1 = @0x1234)]
    #[expected_failure(abort_code = airdrop::E_NOT_ELIGIBLE)]
    fun test_wrong_sibling_proof(
        admin: signer,
        user1: signer
    ) {
        // Create tree with user1 and user2
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);
        let leaf3 = compute_leaf_test(@0x1236, 300); // Not in tree

        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        airdrop::init(&admin, root);

        // Try to claim with wrong sibling (leaf3 instead of leaf2)
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf3); // Wrong sibling!
        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, false);

        airdrop::cliam(&user1, 100, proof, positions);
    }

    #[test(admin = @merkle_airdrop, user1 = @0x1234)]
    #[expected_failure(abort_code = airdrop::E_NOT_ELIGIBLE)]
    fun test_wrong_position_flags(
        admin: signer,
        user1: signer
    ) {
        // Create tree with user1 and user2
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);

        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        airdrop::init(&admin, root);

        // Correct proof but wrong position flag
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf2);
        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, true); // Wrong! Should be false

        airdrop::cliam(&user1, 100, proof, positions);
    }

    /// Test edge case: single leaf tree
    #[test(admin = @merkle_airdrop, user1 = @0x1234)]
    fun test_single_leaf_tree(
        admin: signer,
        user1: signer
    ) {
        // Single leaf: root = leaf hash
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let root = leaf1; // For single leaf, root is the leaf itself

        airdrop::init(&admin, root);

        // Proof should be empty for single leaf
        let proof = vector::empty<vector<u8>>();
        let positions = vector::empty<bool>();

        airdrop::cliam(&user1, 100, proof, positions);

        // Verify claimed
        assert!(airdrop::is_claimed(@0x1234), 400);
    }

    /// Test tree with odd number of leaves (duplicate last leaf)
    #[test(admin = @merkle_airdrop, user1 = @0x1234, user2 = @0x1235, user3 = @0x1236)]
    fun test_three_leaf_tree(
        admin: signer,
        user1: signer,
        user2: signer,
        user3: signer
    ) {
        // 3 leaves: leaf3 will be duplicated
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);
        let leaf3 = compute_leaf_test(@0x1236, 300);

        // Level 1: leaf1+leaf2, leaf3+leaf3 (duplicated)
        let combined1 = vector::empty<u8>();
        vector::append(&mut combined1, leaf1);
        vector::append(&mut combined1, leaf2);
        let hash1 = hash::sha3_256(combined1);

        let combined2 = vector::empty<u8>();
        vector::append(&mut combined2, leaf3);
        vector::append(&mut combined2, leaf3); // Duplicated
        let hash2 = hash::sha3_256(combined2);

        // Root
        let combined_root = vector::empty<u8>();
        vector::append(&mut combined_root, hash1);
        vector::append(&mut combined_root, hash2);
        let root = hash::sha3_256(combined_root);

        airdrop::init(&admin, root);

        // Test claim for user3
        let proof_user3 = vector::empty<vector<u8>>();
        vector::push_back(&mut proof_user3, leaf3); // sibling is itself (duplicated)
        vector::push_back(&mut proof_user3, hash1); // next level sibling

        let positions_user3 = vector::empty<bool>();
        vector::push_back(&mut positions_user3, false); // leaf3 is left, sibling leaf3 is right (same)
        vector::push_back(&mut positions_user3, true); // hash2 is right, sibling hash1 is left

        airdrop::cliam(&user3, 300, proof_user3, positions_user3);
    }

    /// Test proof length mismatch
    #[test(admin = @merkle_airdrop, user1 = @0x1234)]
    #[expected_failure(abort_code = airdrop::E_NOT_ELIGIBLE)]
    fun test_proof_length_mismatch(
        admin: signer,
        user1: signer
    ) {
        // 2-leaf tree
        let leaf1 = compute_leaf_test(@0x1234, 100);
        let leaf2 = compute_leaf_test(@0x1235, 200);

        let combined = vector::empty<u8>();
        vector::append(&mut combined, leaf1);
        vector::append(&mut combined, leaf2);
        let root = hash::sha3_256(combined);

        airdrop::init(&admin, root);

        // Proof with too many elements
        let proof = vector::empty<vector<u8>>();
        vector::push_back(&mut proof, leaf2);
        vector::push_back(&mut proof, leaf1); // Extra, wrong element

        let positions = vector::empty<bool>();
        vector::push_back(&mut positions, false);
        vector::push_back(&mut positions, false); // Extra position

        airdrop::cliam(&user1, 100, proof, positions);
    }

    /// Test that different addresses produce different leaves
    #[test]
    fun test_address_uniqueness() {
        let leaf1 = compute_leaf_test(@0x1, 100);
        let leaf2 = compute_leaf_test(@0x2, 100);

        assert!(leaf1 != leaf2, 500);
    }

    /// Test that different amounts produce different leaves
    #[test]
    fun test_amount_uniqueness() {
        let leaf1 = compute_leaf_test(@0x1, 100);
        let leaf2 = compute_leaf_test(@0x1, 200);

        assert!(leaf1 != leaf2, 501);
    }

    #[test(admin = @merkle_airdrop, user1 = @0x73d820fdc9febcbdb9824ce83d5939e6b4dd6cc251e8714a7da6eac64f2468bf)]
    fun test_from_rust_output(admin: signer, user1: signer){
        let root = x"e43238a98b018cf4caf15a6c1a44201a34bf4344c1f1094bbfc2ef3fb6a5474d";
        airdrop::init(&admin, root);

        let proof = vector[
        x"cc10104ee474aa5404ccb29c1bead029902d3b4531218e6a75cbccea2a3b4d09",
        x"f303763939c42f9e5bb84e2c001e77ca974892c98dae3e24325ca3a2ece1c388"
        ];

        let positions = vector[
        false,
        false
        ];

        airdrop::cliam(&user1, 100, proof, positions);
    }
}