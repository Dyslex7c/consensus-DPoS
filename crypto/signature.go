package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
)

const (
	SignatureSize = ed25519.SignatureSize
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  []byte
}

// MerkleTree represents a complete Merkle tree structure for transaction verification
type MerkleTree struct {
	Root      *MerkleNode
	Leaves    []*MerkleNode
	TxHashMap map[string]int // Maps transaction hash to leaf index for quick lookups
}

func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func HashToHex(data []byte) string {
	return hex.EncodeToString(Hash(data))
}

func HashFromHex(hexString string) ([]byte, error) {
	return hex.DecodeString(hexString)
}

type BlockHasher struct{}

func NewBlockHasher() *BlockHasher {
	return &BlockHasher{}
}

func (bh *BlockHasher) HashHeader(header *types.BlockHeader) []byte {
	// Create a buffer to serialize the header fields in a deterministic way
	var buf bytes.Buffer

	// Write height as fixed-size uint64 to ensure consistent serialization
	binary.Write(&buf, binary.BigEndian, header.Height)

	// Write previous hash with its length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(header.PreviousHash)))
	buf.Write(header.PreviousHash)

	// Serialize timestamp as Unix nanoseconds for consistency
	binary.Write(&buf, binary.BigEndian, header.Timestamp.UnixNano())

	// Write transaction root with length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(header.TransactionsRoot)))
	buf.Write(header.TransactionsRoot)

	// Write state root with length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(header.StateRoot)))
	buf.Write(header.StateRoot)

	// Write proposer with length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(header.Proposer)))
	buf.Write(header.Proposer)

	// Write epoch as fixed-size uint64
	binary.Write(&buf, binary.BigEndian, header.Epoch)

	return Hash(buf.Bytes())
}

func (bh *BlockHasher) HashBlock(block *types.Block) []byte {
	return bh.HashHeader(&block.Header)
}

type TransactionHasher struct{}

func NewTransactionHasher() *TransactionHasher {
	return &TransactionHasher{}
}

func (th *TransactionHasher) HashTransaction(tx *types.Transaction) []byte {
	// Create a buffer to serialize the transaction fields in a deterministic way
	var buf bytes.Buffer

	// Write sender with length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(tx.Sender)))
	buf.Write(tx.Sender)

	// Write recipient with length prefix
	binary.Write(&buf, binary.BigEndian, uint16(len(tx.Recipient)))
	buf.Write(tx.Recipient)

	// Write amount as fixed-size uint64
	binary.Write(&buf, binary.BigEndian, tx.Amount)

	// Write transaction type as a single byte
	buf.WriteByte(byte(tx.Type))

	// Write data with length prefix
	binary.Write(&buf, binary.BigEndian, uint32(len(tx.Data)))
	buf.Write(tx.Data)

	// Serialize timestamp as Unix nanoseconds for consistency
	binary.Write(&buf, binary.BigEndian, tx.Timestamp.UnixNano())

	// If there's a nonce, include it
	if tx.Nonce > 0 {
		binary.Write(&buf, binary.BigEndian, tx.Nonce)
	}

	return Hash(buf.Bytes())
}

func (th *TransactionHasher) SignTransaction(tx *types.Transaction, privateKey ed25519.PrivateKey) error {
	// Calculate the hash of the transaction
	txHash := th.HashTransaction(tx)

	// Sign the hash
	signature := Sign(privateKey, txHash)

	// Set the signature in the transaction
	tx.Signature = signature

	// Set the ID as the hash
	tx.ID = txHash

	return nil
}

func (th *TransactionHasher) VerifyTransaction(tx *types.Transaction) bool {
	// Save the original signature
	originalSignature := tx.Signature

	// Clear the signature for hashing
	tx.Signature = nil

	// Calculate the hash of the transaction
	txHash := th.HashTransaction(tx)

	// Restore the original signature
	tx.Signature = originalSignature

	// Verify the signature
	sender, err := PublicKeyFromBytes(tx.Sender)
	if err != nil {
		return false
	}

	return Verify(sender, txHash, originalSignature)
}

func NewMerkleTree(transactions []*types.Transaction) (*MerkleTree, error) {
	if len(transactions) == 0 {
		return nil, errors.New("cannot create Merkle tree with no transactions")
	}

	th := NewTransactionHasher()
	var leaves []*MerkleNode
	txHashMap := make(map[string]int)

	// Create leaf nodes from transaction hashes
	for i, tx := range transactions {
		txHash := th.HashTransaction(tx)
		node := &MerkleNode{
			Left:  nil,
			Right: nil,
			Hash:  txHash,
		}
		leaves = append(leaves, node)
		txHashMap[hex.EncodeToString(txHash)] = i
	}

	// If we have an odd number of transactions, duplicate the last one
	if len(leaves)%2 != 0 && len(leaves) > 1 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build the tree bottom-up
	root := buildMerkleTree(leaves)

	return &MerkleTree{
		Root:      root,
		Leaves:    leaves,
		TxHashMap: txHashMap,
	}, nil
}

// buildMerkleTree recursively builds the Merkle tree from a list of leaf nodes
func buildMerkleTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 0 {
		return nil
	}

	if len(nodes) == 1 {
		return nodes[0]
	}

	var newLevel []*MerkleNode

	// Process nodes in pairs
	for i := 0; i < len(nodes); i += 2 {
		if i+1 < len(nodes) {
			// Create a parent node with two children
			parentHash := hashPair(nodes[i].Hash, nodes[i+1].Hash)
			parent := &MerkleNode{
				Left:  nodes[i],
				Right: nodes[i+1],
				Hash:  parentHash,
			}
			newLevel = append(newLevel, parent)
		} else {
			// If there's an odd number of nodes, duplicate the last one
			parentHash := hashPair(nodes[i].Hash, nodes[i].Hash)
			parent := &MerkleNode{
				Left:  nodes[i],
				Right: nodes[i], // Self-referencing for odd node
				Hash:  parentHash,
			}
			newLevel = append(newLevel, parent)
		}
	}

	// Recursively build the tree up to the root
	return buildMerkleTree(newLevel)
}

func hashPair(left, right []byte) []byte {
	var data []byte
	data = append(data, left...)
	data = append(data, right...)
	return Hash(data)
}

func (mt *MerkleTree) VerifyTransaction(tx *types.Transaction) (bool, [][]byte) {
	th := NewTransactionHasher()
	txHash := th.HashTransaction(tx)
	hexHash := hex.EncodeToString(txHash)

	// Check if transaction exists in the tree
	leafIndex, exists := mt.TxHashMap[hexHash]
	if !exists {
		return false, nil
	}

	// Get Merkle proof (path to root)
	proof := mt.GenerateMerkleProof(leafIndex)

	// Verify the proof
	return mt.VerifyProof(txHash, proof), proof
}

func (mt *MerkleTree) GenerateMerkleProof(leafIndex int) [][]byte {
	if leafIndex < 0 || leafIndex >= len(mt.Leaves) {
		return nil
	}

	var proof [][]byte
	currentIndex := leafIndex
	levelSize := len(mt.Leaves)
	level := mt.Leaves

	for levelSize > 1 {
		// Determine if we're a left or right child
		isRightChild := currentIndex%2 == 1
		var siblingIndex int

		if isRightChild {
			siblingIndex = currentIndex - 1
		} else {
			siblingIndex = currentIndex + 1
			// Handle case where we might be at the end with no right sibling
			if siblingIndex >= levelSize {
				siblingIndex = currentIndex // Use ourselves as the sibling
			}
		}

		// Add sibling hash to the proof
		proof = append(proof, level[siblingIndex].Hash)

		// Move up to the next level
		currentIndex = currentIndex / 2

		// Calculate nodes for the next level
		var nextLevel []*MerkleNode
		for i := 0; i < levelSize; i += 2 {
			if i+1 < levelSize {
				parentHash := hashPair(level[i].Hash, level[i+1].Hash)
				parent := &MerkleNode{Hash: parentHash}
				nextLevel = append(nextLevel, parent)
			} else {
				// Handle odd number of nodes
				parentHash := hashPair(level[i].Hash, level[i].Hash)
				parent := &MerkleNode{Hash: parentHash}
				nextLevel = append(nextLevel, parent)
			}
		}

		level = nextLevel
		levelSize = len(level)
	}

	return proof
}

func (mt *MerkleTree) VerifyProof(txHash []byte, proof [][]byte) bool {
	currentHash := txHash

	for _, siblingHash := range proof {
		// Determine ordering based on hash comparison (for deterministic ordering)
		if bytes.Compare(currentHash, siblingHash) < 0 {
			// Current hash is smaller, it's the left child
			currentHash = hashPair(currentHash, siblingHash)
		} else {
			// Current hash is larger or equal, it's the right child
			currentHash = hashPair(siblingHash, currentHash)
		}
	}

	// Check if the calculated root matches the stored root
	return bytes.Equal(currentHash, mt.Root.Hash)
}

func (mt *MerkleTree) GetRootHash() []byte {
	if mt.Root == nil {
		return nil
	}
	return mt.Root.Hash
}

func (mt *MerkleTree) GetLeafCount() int {
	return len(mt.Leaves)
}

func (mt *MerkleTree) String() string {
	if mt.Root == nil {
		return "Empty Merkle Tree"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Merkle Tree with %d transactions\n", len(mt.Leaves)))
	sb.WriteString(fmt.Sprintf("Root: %s\n", hex.EncodeToString(mt.Root.Hash)))

	// Print the first few leaf nodes
	maxDisplay := 5
	if len(mt.Leaves) < maxDisplay {
		maxDisplay = len(mt.Leaves)
	}

	sb.WriteString("Leaf nodes (first 5):\n")
	for i := 0; i < maxDisplay; i++ {
		sb.WriteString(fmt.Sprintf("  %d: %s\n", i, hex.EncodeToString(mt.Leaves[i].Hash)))
	}

	if len(mt.Leaves) > maxDisplay {
		sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(mt.Leaves)-maxDisplay))
	}

	return sb.String()
}
