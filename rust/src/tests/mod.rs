#[cfg(test)]
mod tests {
    use crate::merkle_tree::{address_to_bytes, leaf_hash, sha3_256, u64_to_bytes, MerkelTree};

    #[test]
    fn test_address_bytes() {
        // Normal Address
        let address = "0x1234567890abcdef";
        let bytes = address_to_bytes(address);
        assert_eq!(bytes.len(), 32);

        // Odd Length
        let address = "0x123";
        let bytes = address_to_bytes(address);
        assert_eq!(bytes.len(), 32);

        // Without 0x prefix
        let address = "0x1234567890abcdef".trim_start_matches("0x");
        let bytes = address_to_bytes(address);
        assert_eq!(bytes.len(), 32);

        // Empty Address
        let address = "0x";
        let bytes = address_to_bytes(address);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_u64_to_bytes() {
        let amount = 100u64;
        let bytes = u64_to_bytes(amount);
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes, 100u64.to_be_bytes().to_vec());

        // Test with 0
        let bytes = u64_to_bytes(0);
        assert_eq!(bytes, vec![0u8; 8]);

        // Test with max u64
        let bytes = u64_to_bytes(u64::MAX);
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash = sha3_256(data);
        assert_eq!(hash.len(), 32); // SHA3-256 produces 32 bytes

        // Test with empty data
        let hash = sha3_256(&[]);
        assert_eq!(hash.len(), 32);

        // Consistency check
        let hash1 = sha3_256(b"hello");
        let hash2 = sha3_256(b"hello");
        assert_eq!(hash1, hash2);

        let hash3 = sha3_256(b"world");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_leaf_hash(){
        let addr = "0x1234567890abcdef";
        let amount = 100u64;
        let hash = leaf_hash(addr, amount);
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = leaf_hash(addr, amount);
        assert_eq!(hash, hash2);

        // A different amount should produce different hash
        let hash3 = leaf_hash(addr, 200);
        assert_ne!(hash, hash3);

        // Different address should produce different hash
        let hash4 = leaf_hash("0xfedcba0987654321", amount);
        assert_ne!(hash, hash4);
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaf = leaf_hash("0x123", 100);
        let tree = MerkelTree::new(vec![leaf.clone()]);

        // With single leaf, root should be the leaf itself
        assert_eq!(tree.root(), leaf);

        // Proof should be empty for single leaf tree
        let (proof, positions) = tree.generate_proof(0);
        assert!(proof.is_empty());
        assert!(positions.is_empty());
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaves = vec![
            leaf_hash("0x1", 100),
            leaf_hash("0x2", 200),
        ];

        let tree = MerkelTree::new(leaves);

        // Verify tree structure
        assert_eq!(tree.levels.len(), 2); // Leaves level + root level
        assert_eq!(tree.levels[0].len(), 2); // 2 leaves
        assert_eq!(tree.levels[1].len(), 1); // 1 root

        // Generate proof for the first leaf
        let (proof, positions) = tree.generate_proof(0);
        assert_eq!(proof.len(), 1); // One proof element
        assert_eq!(positions.len(), 1);

        // For leaf 0, the sibling is leaf 1, and the position should be false (left)
        assert_eq!(proof[0], tree.levels[0][1]);
        assert_eq!(positions[0], false);

        // Generate proof for the second leaf
        let (proof, positions) = tree.generate_proof(1);
        assert_eq!(proof.len(), 1);
        assert_eq!(positions.len(), 1);

        // For leaf 1, sibling is leaf 0 and the position should be true (right)
        assert_eq!(proof[0], tree.levels[0][0]);
        assert_eq!(positions[0], true);
    }

    #[test]
    fn test_merkle_tree_four_leaves() {
        let users = vec![
            ("0x1", 100u64),
            ("0x2", 200),
            ("0x3", 300),
            ("0x4", 400),
        ];

        let leaves = users.iter()
            .map(|(add, amt)| leaf_hash(add, *amt))
            .collect::<Vec<_>>();

        let tree = MerkelTree::new(leaves.clone());

        // Verify tree structure
        assert_eq!(tree.levels.len(), 3); // Leaves + intermediate + root
        assert_eq!(tree.levels[0].len(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);

        // Test proofs for each leaf
        for i in 0..4 {
            let (proof, positions) = tree.generate_proof(i);

            // Should have 2 proof elements (log2(4) = 2)
            assert_eq!(proof.len(), 2);
            assert_eq!(positions.len(), 2);

            // Verify first level sibling
            let expected_sibling_index = if i % 2 == 0 { i + 1 } else { i - 1 };
            assert_eq!(proof[0], tree.levels[0][expected_sibling_index]);

            // Verify position
            assert_eq!(positions[0], i % 2 == 1);
        }
    }

    #[test]
    fn test_merkle_tree_three_leaves() {
        // Test with odd number of leaves (should duplicate last leaf)
        let leaves = vec![
            leaf_hash("0x1", 100),
            leaf_hash("0x2", 200),
            leaf_hash("0x3", 300),
        ];

        let tree = MerkelTree::new(leaves.clone());

        // Should have 3 levels
        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].len(), 3);
        assert_eq!(tree.levels[1].len(), 2); // Last leaf duplicated
        assert_eq!(tree.levels[2].len(), 1);

        // Test proof for last leaf (index 2)
        let (proof, _) = tree.generate_proof(2);
        assert_eq!(proof.len(), 2);

        // Last leaf's sibling at first level should be itself (duplicated)
        assert_eq!(proof[0], tree.levels[0][2]);
    }

    #[test]
    fn test_merkle_tree_proof_verification() {
        // Test that we can verify a proof by reconstructing the root
        let users = vec![
            ("0x73d820fdc9febcbdb9824ce83d5939e6b4dd6cc251e8714a7da6eac64f2468bf", 100u64),
            ("0x05725e2fd119370a9da4b3afab923f9c35f454c810e175177f06a352de8a26d8", 200),
            ("0x4d2672eca0dcf730350502b9c5f0742cbee0ff10fd69b6c9414407bf15d4b7d1", 300),
            ("0x60db2945ec2e70071427892e671bcb1a242c2e7927d420abdfce4c854d01c6c8", 400),
        ];

        let leaves = users.iter()
            .map(|(add, amt)| leaf_hash(add, *amt))
            .collect::<Vec<_>>();

        let tree = MerkelTree::new(leaves.clone());
        let root = tree.root();

        // Test proof for each leaf
        for i in 0..users.len() {
            let (proof, positions) = tree.generate_proof(i);

            // Reconstruct the root from leaf and proof
            let mut current_hash = leaves[i].clone();

            for (j, sibling) in proof.iter().enumerate() {
                let mut combined = Vec::new();

                if positions[j] {
                    // Current node is right, sibling is left
                    combined.extend(sibling);
                    combined.extend(&current_hash);
                } else {
                    // Current node is left, sibling is right
                    combined.extend(&current_hash);
                    combined.extend(sibling);
                }

                current_hash = sha3_256(&combined);
            }

            // Final hash should match root
            assert_eq!(current_hash, root, "Proof verification failed for a leaf {}", i);
        }
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_generate_proof_out_of_bounds() {
        let leaves = vec![
            leaf_hash("0x1", 100),
            leaf_hash("0x2", 200),
        ];

        let tree = MerkelTree::new(leaves);

        // This should panic since index 2 is out of bounds
        tree.generate_proof(2);
    }

    #[test]
    fn test_merkle_tree_empty() {
        // Test with an empty tree (edge case)
        let tree = MerkelTree::new(vec![]);
        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.levels[0].len(), 0);
        assert_eq!(tree.root(), Vec::<u8>::new());
    }

    #[test]
    fn test_merkle_tree_large() {
        // Test with 8 leaves
        let mut leaves = Vec::new();
        for i in 0..8 {
            leaves.push(leaf_hash(&format!("0x{:x}", i), (i as u64 + 1) * 100));
        }

        let tree = MerkelTree::new(leaves.clone());

        // Should have 4 levels (log2(8) + 1 = 4)
        assert_eq!(tree.levels.len(), 4);

        // Test all proofs
        for i in 0..8 {
            let (proof, _) = tree.generate_proof(i);
            assert_eq!(proof.len(), 3); // log2(8) = 3 proof elements
        }
    }

    #[test]
    fn test_merkle_tree_root_consistency() {
        // Same inputs should produce same root
        let leaves1 = vec![
            leaf_hash("0x1", 100),
            leaf_hash("0x2", 200),
        ];

        let leaves2 = vec![
            leaf_hash("0x1", 100),
            leaf_hash("0x2", 200),
        ];

        let tree1 = MerkelTree::new(leaves1);
        let tree2 = MerkelTree::new(leaves2);

        assert_eq!(tree1.root(), tree2.root());

        // Different order should produce different root
        let leaves3 = vec![
            leaf_hash("0x2", 200),
            leaf_hash("0x1", 100),
        ];

        let tree3 = MerkelTree::new(leaves3);
        assert_ne!(tree1.root(), tree3.root());
    }
}