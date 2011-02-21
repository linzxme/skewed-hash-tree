The Skewed Hash Tree (SHT) library provides data authentication with one digital signature, regardless of the number of blocks. Basically, it creates a binary tree where each leaf contains the cryptographic hash of a data block. The children leaves are concatenated and hashes again, and the resulting value is stored in the parent node. This process goes recursively until it reaches the top of the tree, which is called Root Hash. The root hash is the digital signature over a file that is partitioned in separate blocks.

The benefits of the SHT include:

1) Random size file authentication;
2) Out-of-sequence data block verification;
3) One digital signature to provide authentication and data integrity;
4) Content authentication with the original provider (represented by the digntal signature);

The SHT implementation has three methods, described as follows:

- treehash(MT_context *): it receives a SHT context data structure and returns the root hash value of a file. The input for a MT_context hash the file pointer (file descriptor), the data length, the cryptographic hash function to be used, the block size that the user wants to partition the file, and it will return the data structure with the computed root hash and the authentication path (performed in the next call).

- AP(MT_context *, md_t *ap, int *ap_len): the routine receives the MT_context creates during the treehash procedure and returns the authentication path for a given block in the ap pointer with length in the ap_len. The index of the block is defined in the MT_context->ap_ctx structure.

- verify(u_char *data, int data_len, int index, md_t *root_hash, const EVP_MD *hash_func, md_t *ap, int ap_len): given a data block, its length in bytes, the block index (starting from the left to the right position in the tree), the file root hash, the hash function used in the hash digest, the authentication and its length, the verify routine checks if the given block is authentic, assuming that the signature over the root hash has already been verified.

