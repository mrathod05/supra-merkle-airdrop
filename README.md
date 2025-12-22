# supra-merkle-airdrop

A reference project demonstrating how **Merkle Trees** are used for **whitelisting and airdrops** in blockchain systems, with a clean separation between **off-chain Rust logic** and **on-chain Move smart contracts**.

---

## 📁 Project Structure

```
supra-merkle-airdrop/
│
├── move/
│   ├── Move.toml
│   ├── sources/
│   │   └── airdrop.move
│   └── tests/
│       └── airdrop_tests.move
│
├── rust/
│   ├── Cargo.toml
│   ├── src/
│       ├── merkle_tree/mod.rs
│       ├── tests/mod.rs
│       └── main.rs
└── README.md
```

---

## 🦀 Rust Module

### Purpose
The Rust side is responsible for **off-chain computation**, including:

- Building Merkle Trees
- Hashing leaves (address and amount)
- Generating Merkle proofs
- Verifying proofs locally (for correctness)

### Key Concepts Covered
- SHA-256 / SHA3 hashing
- Deterministic Merkle root generation
- Proof generation with left/right positioning
- Unit testing for Merkle verification

### Example Use Cases
- Preparing whitelist data
- Generating airdrop proofs
- Backend service for a blockchain dApps

### Run Rust Code
```bash
cd rust
cargo test
cargo run
```

---

## 🧬 Move Module

### Purpose
The Move module represents the **on-chain logic**, including:

- Storing a Merkle root
- Verifying Merkle proofs on-chain
- Enforcing airdrop or whitelist rules

### Key Concepts Covered
- Merkle proof verification in Move
- `sha3_256` hashing
- Secure claim validation
- Preventing double claims

### Run Move Tests
```bash
cd move
supra move tool test
```

---

## 🔒 Why Merkle Trees for Airdrops?

Without Merkle Trees:
- Thousands of addresses stored on-chain
- High gas costs
- Poor scalability

With Merkle Trees:
- Only **one 32-byte root stored on-chain**
- Users submit proofs themselves
- Efficient and scalable
---