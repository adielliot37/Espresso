use crate::common::*;
use crate::kv_trait::AuthenticatedKV;
use std::collections::HashMap;
use std::cell::RefCell;

/// Sparse Merkle Tree with deterministic key placement via SHA-256 hashing
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    leaves: HashMap<String, String>,
    hash_cache: RefCell<HashMap<Vec<bool>, Digest>>,
    path_to_key: HashMap<Vec<bool>, String>,
}

/// Proof containing sibling hashes from leaf to root
#[derive(Debug, Clone)]
pub struct SparseMerkleTreeProof {
    siblings: Vec<Digest>,
}

impl SparseMerkleTree {
    /// Convert a key to its deterministic path in the tree.
    /// 
    /// Each bit of H(key) determines whether to go left (false) or right (true).
    /// This ensures each key maps to exactly one leaf position.
    /// 
    /// Security: Relies on preimage resistance of SHA-256 to ensure
    /// different keys map to different positions.
    fn key_to_path(key: &str) -> Vec<bool> {
        let key_hash = hash_one_thing("smt_key", key);
        let bytes = key_hash.as_ref();
        let mut bits = Vec::with_capacity(256);
        
        // Convert hash bytes to bits (MSB first)
        for &byte in bytes {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
                if bits.len() == 256 { break; }
            }
            if bits.len() == 256 { break; }
        }
        
        bits
    }
    
    /// Hash function for leaf nodes containing (key, value) pairs.
    /// 
    /// Uses domain separation to prevent collision attacks between
    /// leaf and branch node hashes.
    fn leaf_hash(key: &str, value: &str) -> Digest {
        hash_two_things("smt_leaf_key", "smt_leaf_value", key, value)
    }
    
    /// Hash function for internal branch nodes.
    /// 
    /// Uses domain separation to prevent collision attacks.
    fn branch_hash(left: Digest, right: Digest) -> Digest {
        hash_two_things("smt_branch_left", "smt_branch_right", left, right)
    }
    
    /// Get the hash at a specific position in the tree.
    /// Position is specified as a path from root to leaf.
    /// If path.len() < 256, this returns the hash of the subtree at that position.
    /// If path.len() == 256, this returns the leaf hash if a key exists there, or zero_digest().
    fn get_hash_at_path(&self, path: &[bool]) -> Digest {
        // Check cache first
        {
            if let Some(&cached_hash) = self.hash_cache.borrow().get(path) {
                return cached_hash;
            }
        }
        
        let hash = if path.len() == 256 {
            // This is a leaf position - check if any key maps here using O(1) lookup
            if let Some(key) = self.path_to_key.get(path) {
                if let Some(value) = self.leaves.get(key) {
                    Self::leaf_hash(key, value)
                } else {
                    zero_digest()
                }
            } else {
                zero_digest() // No key at this position
            }
        } else {
            // For empty trees, avoid deep recursion
            if self.leaves.is_empty() {
                zero_digest()
            } else {
                // Early termination: check if any key could exist in this subtree
                // by checking if any key's path has this prefix
                let has_keys_in_subtree = self.path_to_key.keys().any(|key_path| {
                    key_path.len() > path.len() && key_path[..path.len()] == *path
                });
                
                if !has_keys_in_subtree {
                    zero_digest()
                } else {
                    // This is an internal node - compute hash of left and right children
                    let mut left_path = path.to_vec();
                    left_path.push(false);
                    let left_hash = self.get_hash_at_path(&left_path);
                    
                    let mut right_path = path.to_vec();
                    right_path.push(true);
                    let right_hash = self.get_hash_at_path(&right_path);
                    
                    // Zero-subtree pruning: if both children are zero, result is zero
                    if left_hash == zero_digest() && right_hash == zero_digest() {
                        zero_digest()
                    } else {
                        Self::branch_hash(left_hash, right_hash)
                    }
                }
            }
        };
        
        // Cache the result
        self.hash_cache.borrow_mut().insert(path.to_vec(), hash);
        hash
    }
}

impl AuthenticatedKV for SparseMerkleTree {
    type K = String;
    type V = String;
    type LookupProof = SparseMerkleTreeProof;
    type Commitment = Digest;
    
    /// Create a new empty Sparse Merkle Tree.
    fn new() -> Self {
        SparseMerkleTree {
            leaves: HashMap::new(),
            hash_cache: RefCell::new(HashMap::new()),
            path_to_key: HashMap::new(),
        }
    }
    
    /// Compute the commitment (root hash) of the tree.
    /// 
    /// The commitment uniquely identifies the tree contents due to
    /// collision resistance of the underlying hash function.
    fn commit(&self) -> Self::Commitment {
        self.get_hash_at_path(&[])
    }
    
    /// Insert or update a key-value pair.
    /// 
    /// Returns a new tree with the updated mapping.
    /// The tree structure is deterministic based on key hashes.
    fn insert(mut self, key: Self::K, value: Self::V) -> Self {
        let path = Self::key_to_path(&key);
        self.leaves.insert(key.clone(), value);
        self.path_to_key.insert(path, key);
        self.hash_cache.borrow_mut().clear(); // Clear cache since tree structure changed
        self
    }
    
  
    fn get(&self, key: Self::K) -> (Option<Self::V>, Self::LookupProof) {
        let path = Self::key_to_path(&key);
        let mut siblings = Vec::with_capacity(256);

        // Generate sibling hashes along the path from root to leaf
        for depth in 0..256 {
            // Sibling path: same prefix up to depth, then opposite bit
            let mut sibling_path = path[..depth].to_vec();
            sibling_path.push(!path[depth]); // Flip the bit at this depth

            // Compute the hash of the sibling subtree
            let sibling_hash = self.get_hash_at_path(&sibling_path);
            siblings.push(sibling_hash);
        }
        // The siblings vector is currently in root-to-leaf order.
        // Reverse it so that it is in leaf-to-root order for proof verification.
        siblings.reverse();

        let result = self.leaves.get(&key).cloned();
        let proof = SparseMerkleTreeProof { siblings };

        (result, proof)
    }
    
    /// Verify a proof against a commitment.

    /// 
    /// Verification works by reconstructing the path from leaf to root:
    /// 1. Start with leaf hash (actual value or zero for non-membership)
    /// 2. At each level, combine with sibling hash to get parent hash
    /// 3. Check if final result matches the given commitment
    fn check_proof(
        key: Self::K,
        res: Option<Self::V>, 
        pf: &Self::LookupProof,
        comm: &Self::Commitment,
    ) -> Option<()> {
        if pf.siblings.len() != 256 {
            return None; // Invalid proof length
        }
        
        let path = Self::key_to_path(&key);
        
        // Start with the leaf hash
        let mut current_hash = match res {
            Some(ref value) => Self::leaf_hash(&key, value),
            None => zero_digest(),  // Non-membership proof
        };
        
        // Walk up the tree using sibling hashes to reconstruct root
        // This must exactly match the logic in get_hash_at_path, including zero-subtree pruning
        for (depth, &sibling_hash) in pf.siblings.iter().enumerate() {
            let is_right_child = path[255 - depth];
            // Zero-subtree pruning: if both children are zero, result is zero
            if current_hash == zero_digest() && sibling_hash == zero_digest() {
                current_hash = zero_digest();
            } else if is_right_child {
                // We're the right child, sibling is on the left
                current_hash = Self::branch_hash(sibling_hash, current_hash);
            } else {
                // We're the left child, sibling is on the right
                current_hash = Self::branch_hash(current_hash, sibling_hash);
            }
        }
        
        // Verification succeeds if we reconstructed the expected root hash
        if current_hash == *comm {
            Some(())
        } else {
            None
        }
    }
    
    /// Remove a key from the tree.
    /// 
    /// Returns a new tree without the specified key.
    fn remove(mut self, key: Self::K) -> Self {
        let path = Self::key_to_path(&key);
        self.leaves.remove(&key);
        self.path_to_key.remove(&path);
        self.hash_cache.borrow_mut().clear(); // Clear cache since tree structure changed
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv_trait::AuthenticatedKV;
    use quickcheck::{quickcheck, Arbitrary, Gen};
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    enum SMTOp {
        Insert(String, String),
        Get(String),
        Remove(String),
    }

    impl Arbitrary for SMTOp {
        fn arbitrary(g: &mut Gen) -> Self {
            // Use smaller key space to exercise collisions and edge cases more
            let key_choices = ["", "a", "b", "c", "key1", "key2", "test", "0", "1"];
            let key = g.choose(&key_choices).unwrap().to_string();
            let value = String::arbitrary(g);
            
            match g.choose(&[0, 1, 2]).unwrap() {
                0 => SMTOp::Insert(key, value),
                1 => SMTOp::Get(key),
                _ => SMTOp::Remove(key),
            }
        }
        
        fn shrink(&self) -> Box<dyn Iterator<Item = Self> + 'static> {
            match self.clone() {
                SMTOp::Insert(k, v) => {
                    let k_clone = k.clone();
                    let v_clone = v.clone();
                    Box::new(
                        k.shrink().map(move |k2| SMTOp::Insert(k2, v_clone.clone()))
                            .chain(v.shrink().map(move |v2| SMTOp::Insert(k_clone.clone(), v2)))
                    )
                }
                SMTOp::Get(k) => Box::new(k.shrink().map(SMTOp::Get)),
                SMTOp::Remove(k) => Box::new(k.shrink().map(SMTOp::Remove)),
            }
        }
    }

    /// Test basic functionality against a reference HashMap
    fn test_smt_vs_hashmap(ops: Vec<SMTOp>) {
        let mut smt = SparseMerkleTree::new();
        let mut reference_map: HashMap<String, String> = HashMap::new();
        
        for op in ops {
            match op {
                SMTOp::Insert(key, value) => {
                    smt = smt.insert(key.clone(), value.clone());
                    reference_map.insert(key, value);
                }
                SMTOp::Get(key) => {
                    let (smt_result, proof) = smt.get(key.clone());
                    let reference_result = reference_map.get(&key).cloned();
                    
                    // Results should match
                    assert_eq!(smt_result, reference_result, "Lookup result mismatch for key: {}", key);
                    
                    // Proof should verify
                    let commit = smt.commit();
                    assert!(
                        SparseMerkleTree::check_proof(key.clone(), smt_result, &proof, &commit).is_some(),
                        "Proof verification failed for key: {}", key
                    );
                }
                SMTOp::Remove(key) => {
                    smt = smt.remove(key.clone());
                    reference_map.remove(&key);
                }
            }
        }
    }

    #[quickcheck]
    fn smt_vs_hashmap_quickcheck(ops: Vec<SMTOp>) {
        test_smt_vs_hashmap(ops);
    }

    #[test]
    fn test_basic_operations() {
        let mut smt = SparseMerkleTree::new();
        
        // Test empty tree
        let empty_commit = smt.commit();
        let (result, proof) = smt.get("nonexistent".to_string());
        assert_eq!(result, None);
        assert!(SparseMerkleTree::check_proof(
            "nonexistent".to_string(), 
            None, 
            &proof, 
            &empty_commit
        ).is_some());
        
        // Test single insertion
        smt = smt.insert("key1".to_string(), "value1".to_string());
        let commit1 = smt.commit();
        
        let (result, proof) = smt.get("key1".to_string());
        assert_eq!(result, Some("value1".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "key1".to_string(),
            result,
            &proof,
            &commit1
        ).is_some());
        
        // Test non-existent key with non-empty tree
        let (result, proof) = smt.get("key2".to_string());
        assert_eq!(result, None);
        assert!(SparseMerkleTree::check_proof(
            "key2".to_string(),
            None,
            &proof,
            &commit1
        ).is_some());
        
        // Test multiple insertions
        smt = smt.insert("key2".to_string(), "value2".to_string());
        smt = smt.insert("key3".to_string(), "value3".to_string());
        let commit2 = smt.commit();
        
        // Verify all keys
        for (key, expected_value) in [("key1", "value1"), ("key2", "value2"), ("key3", "value3")] {
            let (result, proof) = smt.get(key.to_string());
            assert_eq!(result, Some(expected_value.to_string()));
            assert!(SparseMerkleTree::check_proof(
                key.to_string(),
                result,
                &proof,
                &commit2
            ).is_some());
        }
    }

    #[test]
    fn test_key_update() {
        let mut smt = SparseMerkleTree::new();
        
        // Insert initial value
        smt = smt.insert("key".to_string(), "value1".to_string());
        let commit1 = smt.commit();
        
        // Update with new value
        smt = smt.insert("key".to_string(), "value2".to_string());
        let commit2 = smt.commit();
        
        // Commits should be different
        assert_ne!(commit1, commit2);
        
        // Should get updated value
        let (result, proof) = smt.get("key".to_string());
        assert_eq!(result, Some("value2".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "key".to_string(),
            result,
            &proof,
            &commit2
        ).is_some());
    }

    #[test]
    fn test_removal() {
        let mut smt = SparseMerkleTree::new();
        
        // Insert some keys
        smt = smt.insert("key1".to_string(), "value1".to_string());
        smt = smt.insert("key2".to_string(), "value2".to_string());
        let commit_before = smt.commit();
        
        // Remove one key
        smt = smt.remove("key1".to_string());
        let commit_after = smt.commit();
        
        // Commits should be different
        assert_ne!(commit_before, commit_after);
        
        // Removed key should not be found
        let (result, proof) = smt.get("key1".to_string());
        assert_eq!(result, None);
        assert!(SparseMerkleTree::check_proof(
            "key1".to_string(),
            None,
            &proof,
            &commit_after
        ).is_some());
        
        // Other key should still be there
        let (result, proof) = smt.get("key2".to_string());
        assert_eq!(result, Some("value2".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "key2".to_string(),
            result,
            &proof,
            &commit_after
        ).is_some());
    }

    #[test]
    fn test_commitment_determinism() {
        // Same operations in different orders should yield same commitment
        let mut smt1 = SparseMerkleTree::new();
        smt1 = smt1.insert("a".to_string(), "1".to_string());
        smt1 = smt1.insert("b".to_string(), "2".to_string());
        smt1 = smt1.insert("c".to_string(), "3".to_string());
        
        let mut smt2 = SparseMerkleTree::new();
        smt2 = smt2.insert("c".to_string(), "3".to_string());
        smt2 = smt2.insert("a".to_string(), "1".to_string());
        smt2 = smt2.insert("b".to_string(), "2".to_string());
        
        assert_eq!(smt1.commit(), smt2.commit());
    }

    #[test]
    fn test_empty_tree_properties() {
        let smt = SparseMerkleTree::new();
        let empty_commit = smt.commit();
        
        // Any lookup in empty tree should return None with valid proof
        let (result, proof) = smt.get("any_key".to_string());
        assert_eq!(result, None);
        assert!(SparseMerkleTree::check_proof(
            "any_key".to_string(),
            None,
            &proof,
            &empty_commit
        ).is_some());
    }

    #[test]
    fn test_proof_manipulation_fails() {
        let mut smt = SparseMerkleTree::new();
        smt = smt.insert("key".to_string(), "value".to_string());
        let commit = smt.commit();
        
        let (result, mut proof) = smt.get("key".to_string());
        
        // Manipulate the proof and ensure verification fails
        if !proof.siblings.is_empty() {
            // Instead of setting to zero_digest (which might be the correct value),
            // corrupt it by flipping some bits to ensure it's definitely wrong
            let mut corrupted_sibling = proof.siblings[0];
            if corrupted_sibling == zero_digest() {
                // If it's zero, make it non-zero
                corrupted_sibling = SparseMerkleTree::leaf_hash("dummy", "dummy");
            } else {
                // If it's non-zero, make it zero
                corrupted_sibling = zero_digest();
            }
            proof.siblings[0] = corrupted_sibling;
            
            assert!(SparseMerkleTree::check_proof(
                "key".to_string(),
                result.clone(),
                &proof,
                &commit
            ).is_none());
        }
    }

    #[test]
    fn test_wrong_commitment_fails() {
        let mut smt1 = SparseMerkleTree::new();
        smt1 = smt1.insert("key".to_string(), "value".to_string());
        
        let mut smt2 = SparseMerkleTree::new();
        smt2 = smt2.insert("key".to_string(), "different_value".to_string());
        
        let (result, proof) = smt1.get("key".to_string());
        let wrong_commit = smt2.commit();
        
        // Proof from smt1 should not verify against smt2's commitment
        assert!(SparseMerkleTree::check_proof(
            "key".to_string(),
            result,
            &proof,
            &wrong_commit
        ).is_none());
    }

    #[test]
    fn test_non_membership_proofs() {
        let mut smt = SparseMerkleTree::new();
        smt = smt.insert("existing_key".to_string(), "value".to_string());
        let commit = smt.commit();
        
        // Proof of non-membership should verify
        let (result, proof) = smt.get("non_existing_key".to_string());
        assert_eq!(result, None);
        assert!(SparseMerkleTree::check_proof(
            "non_existing_key".to_string(),
            None,
            &proof,
            &commit
        ).is_some());
        
        // But claiming the non-existing key has a value should fail
        assert!(SparseMerkleTree::check_proof(
            "non_existing_key".to_string(),
            Some("fake_value".to_string()),
            &proof,
            &commit
        ).is_none());
    }

    #[test]
    fn test_specific_edge_cases() {
        use SMTOp::*;
        
        // Test cases that might reveal bugs
        test_smt_vs_hashmap(vec![
            Insert("".to_string(), "empty_key".to_string()),
            Get("".to_string()),
            Insert("a".to_string(), "".to_string()), // empty value
            Get("a".to_string()),
        ]);
        
        // Test same key inserted multiple times
        test_smt_vs_hashmap(vec![
            Insert("key".to_string(), "value1".to_string()),
            Insert("key".to_string(), "value2".to_string()),
            Insert("key".to_string(), "value3".to_string()),
            Get("key".to_string()),
        ]);
        
        // Test remove non-existent key
        test_smt_vs_hashmap(vec![
            Remove("non_existent".to_string()),
            Get("non_existent".to_string()),
        ]);
    }
}