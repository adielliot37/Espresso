# Task 1




## The Basic Idea

A sparse Merkle tree is essentially a binary tree where we can store key-value pairs, but here's the clever part: every possible key gets mapped to exactly one specific leaf position. We're not just throwing keys wherever we feel like it.

## How Keys Map to Unique Leaves

The magic happens through hashing. When we have a key K, we don't just randomly pick a spot for it. Instead, we compute index(K) = H(K), where H is our hash function (like SHA-256). This gives us a fixed-length bit string that we read like a roadmap - each bit tells us whether to go left (0) or right (1) as we walk down the tree.

Now here's why this guarantees uniqueness: SHA-256 has something called **preimage resistance**. In simple terms, this means if K ≠ K', then H(K) ≠ H(K'). So two different keys will always hash to different values, which means they'll always end up in different leaves. No collisions, no overlap.

## The Empty Subtree Trick

Here's where it gets interesting. Instead of actually storing a massive tree with 2^256 possible positions, we represent any completely empty subtree with just ε = 0^n (all zeros). This works because of **collision resistance**. We're basically betting that no legitimate leaf hash will ever accidentally produce all zeros. Given how hash functions work, this is an extremely safe bet - the probability is astronomically small.

The assumption we're relying on is that D_leaf(K,V) ≠ ε for any valid (K,V) pair.

## Building the Tree

We construct our tree bottom-up using these rules:
- D_leaf(K,V) = H_leaf(K || V) for hashing the key-value pair
- D_branch(L,R) = H_branch(L || R) for hashing left and right children  
- root = D_root for the final root digest

Where || means concatenation.

## Why Collision-Resistance Matters

Here's the security argument that makes this whole thing work. Suppose someone tried to fool us by creating two different sparse Merkle trees T and T' that differ by exactly one key-value pair but somehow have the same root digest. Mathematically, this would mean root(T) = root(T') but T ≠ T'.

If this ever happened, we'd have found two different inputs to our hash function that produce the same output. But that's exactly what collision-resistance promises won't happen with SHA-256.

So either our trees actually are identical (contradiction) or we just broke SHA-256's collision-resistance (extremely unlikely). This gives us confidence that if two sparse Merkle trees have the same root digest, they must represent exactly the same set of key-value pairs.

## Why This Design is Clever

The beautiful thing about sparse Merkle trees is that they give us:
- **Deterministic structure**: Every key always goes to the same place
- **Efficient storage**: We only store the parts we actually use
- **Strong security**: Breaking the tree means breaking the underlying hash function
- **Simple proofs**: We can prove membership or non-membership efficiently

