package network

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/crypto"
)

// MessageType defines the type of message in the P2P network
type MessageType uint8

const (
	// Control message types
	MessageTypeHandshake MessageType = iota
	MessageTypePing
	MessageTypePong
	MessageTypeGetPeers
	MessageTypePeers
	MessageTypePeerRequest
	MessageTypePeerResponse
	MessageTypeDisconnect

	// Data message types
	MessageTypeTransaction
	MessageTypeBlock
	MessageTypeBlockRequest
	MessageTypeBlockResponse
	MessageTypeTransactionRequest
	MessageTypeTransactionResponse
	MessageTypeValidatorAnnouncement
	MessageTypeConsensusVote
)

// Protocol version
const (
	ProtocolVersion    = uint16(1)
	MaxMessageSize     = 1024 * 1024 * 10 // 10MB
	HandshakeTimeout   = 5 * time.Second
	PingInterval       = 30 * time.Second
	PongTimeout        = 10 * time.Second
	ConnectionTimeout  = 60 * time.Second
	DisconnectTimeout  = 5 * time.Second
	MaxPendingMessages = 1000
)

// Error types
var (
	ErrMessageTooLarge     = errors.New("message exceeds maximum size")
	ErrInvalidMessageType  = errors.New("invalid message type")
	ErrInvalidMessageData  = errors.New("invalid message data")
	ErrMessageTimeout      = errors.New("message timeout")
	ErrInvalidSignature    = errors.New("invalid message signature")
	ErrHandshakeTimeout    = errors.New("handshake timeout")
	ErrPeerDisconnected    = errors.New("peer disconnected")
	ErrProtocolMismatch    = errors.New("protocol version mismatch")
	ErrNetworkIDMismatch   = errors.New("network ID mismatch")
	ErrPingTimeout         = errors.New("ping timeout")
	ErrNoPendingConnection = errors.New("no pending connection")
)

// Message represents a P2P message
type Message struct {
	Type      MessageType `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      []byte      `json:"data"`
	Signature []byte      `json:"signature"`
	SenderID  []byte      `json:"sender_id"`
}

// NewMessage creates a new message of the specified type with the given data
func NewMessage(msgType MessageType, data []byte, privateKey ed25519.PrivateKey) (*Message, error) {
	if len(data) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	msg := &Message{
		Type:      msgType,
		Timestamp: time.Now(),
		Data:      data,
		SenderID:  privateKey.Public().(ed25519.PublicKey),
	}

	// Sign the message
	sig, err := msg.sign(privateKey)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig

	return msg, nil
}

// Serialize converts the message to bytes
func (m *Message) Serialize() ([]byte, error) {
	return json.Marshal(m)
}

// DeserializeMessage converts bytes back to a message
func DeserializeMessage(data []byte) (*Message, error) {
	msg := &Message{}
	if err := json.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// sign signs the message with the given private key
func (m *Message) sign(privateKey ed25519.PrivateKey) ([]byte, error) {
	// Create a buffer with all fields except signature
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint8(m.Type))
	binary.Write(&buf, binary.BigEndian, m.Timestamp.UnixNano())
	binary.Write(&buf, binary.BigEndian, uint32(len(m.Data)))
	buf.Write(m.Data)
	buf.Write(m.SenderID)

	// Sign the buffer
	return crypto.Sign(privateKey, buf.Bytes()), nil
}

// Verify checks the message signature
func (m *Message) Verify() bool {
	// Create a buffer with all fields except signature
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint8(m.Type))
	binary.Write(&buf, binary.BigEndian, m.Timestamp.UnixNano())
	binary.Write(&buf, binary.BigEndian, uint32(len(m.Data)))
	buf.Write(m.Data)
	buf.Write(m.SenderID)

	// Verify the signature
	senderKey, err := crypto.PublicKeyFromBytes(m.SenderID)
	if err != nil {
		return false
	}

	return crypto.Verify(senderKey, buf.Bytes(), m.Signature)
}

// HandshakeData contains information for the initial peer handshake
type HandshakeData struct {
	ProtocolVersion uint16 `json:"protocol_version"`
	NetworkID       string `json:"network_id"`
	NodeID          string `json:"node_id"`
	ListenAddr      string `json:"listen_addr"`
	IsValidator     bool   `json:"is_validator"`
}

// NewHandshakeData creates handshake data
func NewHandshakeData(networkID, nodeID, listenAddr string, isValidator bool) *HandshakeData {
	return &HandshakeData{
		ProtocolVersion: ProtocolVersion,
		NetworkID:       networkID,
		NodeID:          nodeID,
		ListenAddr:      listenAddr,
		IsValidator:     isValidator,
	}
}

// PeerInfo contains information about a peer
type PeerInfo struct {
	NodeID      string `json:"node_id"`
	Address     string `json:"address"`
	IsValidator bool   `json:"is_validator"`
}

// PeerList is a list of peers
type PeerList struct {
	Peers []PeerInfo `json:"peers"`
}

// BlockRequest is used to request blocks
type BlockRequest struct {
	StartHeight uint64 `json:"start_height"`
	EndHeight   uint64 `json:"end_height"`
}

// BlockResponse contains blocks in response to a BlockRequest
type BlockResponse struct {
	Blocks []types.Block `json:"blocks"`
}

// TransactionRequest is used to request transactions
type TransactionRequest struct {
	TxIDs [][]byte `json:"tx_ids"`
}

// TransactionResponse contains transactions in response to a TransactionRequest
type TransactionResponse struct {
	Transactions []types.Transaction `json:"transactions"`
}

// ValidatorAnnouncement is used by validators to announce themselves
type ValidatorAnnouncement struct {
	ValidatorInfo types.Validator `json:"validator_info"`
}

// ConsensusVote represents a vote in the consensus process
type ConsensusVote struct {
	BlockHash []byte    `json:"block_hash"`
	Height    uint64    `json:"height"`
	Round     uint32    `json:"round"`
	VoteType  VoteType  `json:"vote_type"`
	Timestamp time.Time `json:"timestamp"`
}

// VoteType defines the type of consensus vote
type VoteType uint8

const (
	VoteTypePrevote VoteType = iota
	VoteTypePrecommit
)

// Encode various message data types to bytes
func EncodeHandshakeData(data *HandshakeData) ([]byte, error) {
	return json.Marshal(data)
}

func EncodePeerList(data *PeerList) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeBlockRequest(data *BlockRequest) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeBlockResponse(data *BlockResponse) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeTransactionRequest(data *TransactionRequest) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeTransactionResponse(data *TransactionResponse) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeValidatorAnnouncement(data *ValidatorAnnouncement) ([]byte, error) {
	return json.Marshal(data)
}

func EncodeConsensusVote(data *ConsensusVote) ([]byte, error) {
	return json.Marshal(data)
}

// Decode various message data types from bytes
func DecodeHandshakeData(data []byte) (*HandshakeData, error) {
	var result HandshakeData
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode handshake data: %w", err)
	}
	return &result, nil
}

func DecodePeerList(data []byte) (*PeerList, error) {
	var result PeerList
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode peer list: %w", err)
	}
	return &result, nil
}

func DecodeBlockRequest(data []byte) (*BlockRequest, error) {
	var result BlockRequest
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode block request: %w", err)
	}
	return &result, nil
}

func DecodeBlockResponse(data []byte) (*BlockResponse, error) {
	var result BlockResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode block response: %w", err)
	}
	return &result, nil
}

func DecodeTransactionRequest(data []byte) (*TransactionRequest, error) {
	var result TransactionRequest
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode transaction request: %w", err)
	}
	return &result, nil
}

func DecodeTransactionResponse(data []byte) (*TransactionResponse, error) {
	var result TransactionResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode transaction response: %w", err)
	}
	return &result, nil
}

func DecodeValidatorAnnouncement(data []byte) (*ValidatorAnnouncement, error) {
	var result ValidatorAnnouncement
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode validator announcement: %w", err)
	}
	return &result, nil
}

func DecodeConsensusVote(data []byte) (*ConsensusVote, error) {
	var result ConsensusVote
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode consensus vote: %w", err)
	}
	return &result, nil
}

// String returns a string representation of a message type
func (t MessageType) String() string {
	switch t {
	case MessageTypeHandshake:
		return "Handshake"
	case MessageTypePing:
		return "Ping"
	case MessageTypePong:
		return "Pong"
	case MessageTypePeerRequest:
		return "PeerRequest"
	case MessageTypePeerResponse:
		return "PeerResponse"
	case MessageTypeDisconnect:
		return "Disconnect"
	case MessageTypeTransaction:
		return "Transaction"
	case MessageTypeBlock:
		return "Block"
	case MessageTypeBlockRequest:
		return "BlockRequest"
	case MessageTypeBlockResponse:
		return "BlockResponse"
	case MessageTypeTransactionRequest:
		return "TransactionRequest"
	case MessageTypeTransactionResponse:
		return "TransactionResponse"
	case MessageTypeValidatorAnnouncement:
		return "ValidatorAnnouncement"
	case MessageTypeConsensusVote:
		return "ConsensusVote"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
