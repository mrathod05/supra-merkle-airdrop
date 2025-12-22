use std::fs;
use serde::{Deserialize};
use anyhow::{Context, Result};
use tracing::info;
use crate::merkle_tree::{leaf_hash, MerkelTree};

mod tests;
mod merkle_tree;

const INPUT_FILE: &str = "../users.json";
const MERKLE_ROOT_FILE: &str = "./merkle_root.txt";
const MERKLE_PROOF_FILE: &str = "./merkle_proof.json";

// Struct to deserialize JSON
#[derive(Debug, Deserialize)]
struct User {
    address: String,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct UserData {
    users: Vec<User>,
}


fn main()-> Result<()> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Read the JSON file
    let json_content = fs::read_to_string(INPUT_FILE).context(format!("Failed to read {}", INPUT_FILE))?;
    let user_data: UserData = serde_json::from_str(&json_content).context("Failed to parse JSON")?;

    // Build leaves
    let leaves = user_data.users
        .iter()
        .map(|user| leaf_hash(&user.address, user.amount))
        .collect::<Vec<_>>();

    let tree = MerkelTree::new(leaves);
    info!("Merkle Root: 0x{}", hex::encode(tree.root()));

    let root_hex = hex::encode(tree.root());
    fs::write(MERKLE_ROOT_FILE, &root_hex)?;
    info!("Root saved to merkle_root.txt");

    let mut proofs = Vec::new();
    for (index, user) in user_data.users.iter().enumerate() {
        let (proof, positions) = tree.generate_proof(index);

        let proof_hex: Vec<String> = proof.iter()
            .map(|p| hex::encode(p))
            .collect();

        proofs.push(serde_json::json!({
            "address": user.address,
            "amount": user.amount,
            "proof": proof_hex,
            "positions": positions
        }));

        info!("\nProof for user {} ({}):", index, user.address);
        info!("  Positions: {:?}", positions);
        info!("  Proof hashes:");

        for p in &proof_hex {
            info!("    0x{}", p);
        }
    }

    let proofs_json = serde_json::to_string_pretty(&proofs)?;
    fs::write(MERKLE_PROOF_FILE, proofs_json)?;
    info!("\nAll proofs saved to merkle_proofs.json");

    Ok(())
}