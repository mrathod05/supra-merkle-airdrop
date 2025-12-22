use sha3::{Digest, Sha3_256};
#[derive(Debug)]
pub struct MerkelTree {
    pub levels: Vec<Vec<Vec<u8>>>
}

impl MerkelTree {
    pub fn new(leaves: Vec<Vec<u8>>) -> Self {
        let mut levels = vec![leaves];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::new();

            let mut i = 0;
            while i < prev.len() {
                let left = &prev[i];
                let right = if i + 1 < prev.len() { &prev[i + 1] } else { left };

                let mut combined = Vec::new();
                combined.extend(left);
                combined.extend(right);

                let parent_hash = sha3_256(&combined);
                next.push(parent_hash);

                i += 2;
            }

            levels.push(next);
        }

        Self { levels }
    }

    pub fn root(&self) -> Vec<u8> {
        self.levels.last()
            .and_then(|l| l.first())
            .cloned()
             .unwrap_or_default()
    }

    pub(crate) fn generate_proof(&self, mut index: usize) -> (Vec<Vec<u8>>, Vec<bool>) {
        let mut proof = Vec::new();
        let mut positions = Vec::new();

        for level in &self.levels[..self.levels.len() -1] {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            let sibling = if sibling_index < level.len() {
                level[sibling_index].clone()
            }else{
                level[index].clone()
            };

            // if the current node is right, the sibling is left
            positions.push(is_right);
            proof.push(sibling);

            index /=2;
        }

        (proof, positions)
    }
}

pub fn address_to_bytes(add: &str) -> Vec<u8> {
    let mut hex_str = add.trim_start_matches("0x").to_string();

    if hex_str.len() % 2 != 0 {
        hex_str = format!("0{}", hex_str);
    }

    let mut bytes = hex::decode(hex_str).unwrap();
    while bytes.len() < 32 {
        bytes.insert(0, 0u8);
    }

    assert_eq!(bytes.len(), 32);
    bytes
}

pub fn u64_to_bytes(amount: u64) -> Vec<u8> {
    amount.to_be_bytes().to_vec()
}


pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn leaf_hash(add: &str, amount: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(address_to_bytes(add));
    data.extend(u64_to_bytes(amount));
    sha3_256(&data)
}
