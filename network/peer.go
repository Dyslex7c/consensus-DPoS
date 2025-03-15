package network

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// PeerState represents the current state of a peer connection
type PeerState int

const (
	// PeerStateInit indicates an initialized but not connected peer
	PeerStateInit PeerState = iota
	// PeerStateConnecting indicates a peer in the process of connecting
	PeerStateConnecting
	// PeerStateHandshaking indicates a peer in the process of handshaking
	PeerStateHandshaking
	// PeerStateConnected indicates a fully connected and handshaked peer
	PeerStateConnected
	// PeerStateDisconnecting indicates a peer in the process of disconnecting
	PeerStateDisconnecting
	// PeerStateDisconnected indicates a disconnected peer
	PeerStateDisconnected
)

// Peer represents a remote peer in the P2P network
type Peer struct {
	// Peer identification
	NodeID      string             // Unique ID of the peer (derived from public key)
	PublicKey   ed25519.PublicKey  // Peer's public key
	PrivateKey  ed25519.PrivateKey // Peer's private key
	IsValidator bool               // Whether the peer is a validator

	// Network details
	Address    string   // Remote address as host:port
	ListenAddr string   // Address the peer is listening on for incoming connections
	conn       net.Conn // Underlying network connection
	reader     *bufio.Reader
	writer     *bufio.Writer
	lastSeen   time.Time // Last time we received a message from this peer

	// Peer state
	state PeerState

	// Channel for outgoing messages to be sent
	outgoing chan *Message

	// Synchronization
	mutex   sync.RWMutex
	wg      sync.WaitGroup
	closed  bool
	closeCh chan struct{}

	// Callback for received messages
	onReceive func(*Peer, *Message)

	// Logger
	logger *utils.Logger
}

// NewPeer creates a new peer instance
func NewPeer(address string, logger *utils.Logger) *Peer {
	return &Peer{
		Address:  address,
		state:    PeerStateInit,
		outgoing: make(chan *Message, MaxPendingMessages),
		closeCh:  make(chan struct{}),
		lastSeen: time.Now(),
		logger:   logger,
	}
}

// SetMessageCallback sets the callback function for received messages
func (p *Peer) SetMessageCallback(callback func(*Peer, *Message)) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.onReceive = callback
}

// Connect establishes a connection to the peer
func (p *Peer) Connect() error {
	p.mutex.Lock()
	if p.state != PeerStateInit && p.state != PeerStateDisconnected {
		p.mutex.Unlock()
		return fmt.Errorf("cannot connect peer in state %v", p.state)
	}
	p.setState(PeerStateConnecting)
	p.mutex.Unlock()

	// Set connection timeout
	dialer := net.Dialer{Timeout: ConnectionTimeout}
	conn, err := dialer.Dial("tcp", p.Address)
	if err != nil {
		p.setState(PeerStateDisconnected)
		return fmt.Errorf("failed to connect to peer %s: %w", p.Address, err)
	}

	p.mutex.Lock()
	p.conn = conn
	p.reader = bufio.NewReader(conn)
	p.writer = bufio.NewWriter(conn)
	p.mutex.Unlock()

	// Start read/write loops
	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()

	p.setState(PeerStateHandshaking)
	p.logger.Debug("Connected to peer", "address", p.Address)

	return nil
}

// Accept accepts an incoming connection
func (p *Peer) Accept(conn net.Conn) {
	p.mutex.Lock()
	p.conn = conn
	p.Address = conn.RemoteAddr().String()
	p.reader = bufio.NewReader(conn)
	p.writer = bufio.NewWriter(conn)
	p.setState(PeerStateHandshaking)
	p.mutex.Unlock()

	// Start read/write loops
	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()

	p.logger.Debug("Accepted connection from peer", "address", p.Address)
}

// Handshake performs the peer handshake
func (p *Peer) Handshake(networkID string, nodeID string, listenAddr string, isValidator bool, privateKey ed25519.PrivateKey) error {
	handshakeData := NewHandshakeData(networkID, nodeID, listenAddr, isValidator)

	// Encode handshake data
	data, err := EncodeHandshakeData(handshakeData)
	if err != nil {
		return fmt.Errorf("failed to encode handshake data: %w", err)
	}

	// Create and send handshake message
	msg, err := NewMessage(MessageTypeHandshake, data, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create handshake message: %w", err)
	}

	err = p.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to send handshake message: %w", err)
	}

	// Waiting for handshake response happens in the message handling callback

	return nil
}

// HandleHandshake processes a handshake message from a peer
func (p *Peer) HandleHandshake(msg *Message, ownNetworkID string) error {
	// Decode handshake data
	handshakeData, err := DecodeHandshakeData(msg.Data)
	if err != nil {
		return fmt.Errorf("failed to decode handshake data: %w", err)
	}

	// Verify protocol version
	if handshakeData.ProtocolVersion != ProtocolVersion {
		return ErrProtocolMismatch
	}

	// Verify network ID
	if handshakeData.NetworkID != ownNetworkID {
		return ErrNetworkIDMismatch
	}

	// Update peer information
	p.mutex.Lock()
	p.NodeID = handshakeData.NodeID
	p.ListenAddr = handshakeData.ListenAddr
	p.IsValidator = handshakeData.IsValidator

	// If this is the response to our handshake, mark as connected
	if p.state == PeerStateHandshaking {
		p.setState(PeerStateConnected)
	}
	p.mutex.Unlock()

	p.logger.Info("Handshake completed", "nodeID", p.NodeID, "address", p.Address)
	return nil
}

// SendMessage sends a message to the peer
func (p *Peer) SendMessage(msg *Message) error {
	p.mutex.RLock()
	if p.closed {
		p.mutex.RUnlock()
		return ErrPeerDisconnected
	}
	p.mutex.RUnlock()

	select {
	case p.outgoing <- msg:
		return nil
	default:
		return fmt.Errorf("outgoing message queue full for peer %s", p.Address)
	}
}

// readLoop continuously reads messages from the peer
func (p *Peer) readLoop() {
	defer p.wg.Done()
	defer p.Disconnect("Read loop ended")

	for {
		// Check if we should exit
		select {
		case <-p.closeCh:
			return
		default:
			// Continue processing
		}

		// Set read deadline
		p.conn.SetReadDeadline(time.Now().Add(ConnectionTimeout))

		// Read message length (4 bytes)
		var msgLen uint32
		err := binary.Read(p.reader, binary.BigEndian, &msgLen)
		if err != nil {
			p.logger.Debug("Failed to read message length", "error", err)
			return
		}

		// Check message size
		if msgLen > MaxMessageSize {
			p.logger.Warn("Message too large", "size", msgLen)
			return
		}

		// Read message data
		msgData := make([]byte, msgLen)
		_, err = io.ReadFull(p.reader, msgData)
		if err != nil {
			p.logger.Debug("Failed to read message data", "error", err)
			return
		}

		// Deserialize message
		msg, err := DeserializeMessage(msgData)
		if err != nil {
			p.logger.Debug("Failed to deserialize message", "error", err)
			continue
		}

		// Verify message signature
		if !msg.Verify() {
			p.logger.Warn("Invalid message signature from peer", "address", p.Address)
			continue
		}

		// Update last seen time
		p.mutex.Lock()
		p.lastSeen = time.Now()
		p.mutex.Unlock()

		// Handle ping messages internally
		if msg.Type == MessageTypePing {
			// Respond with pong
			p.handlePing(msg)
			continue
		}

		// Handle pong messages internally
		if msg.Type == MessageTypePong {
			// Just update last seen, already done above
			continue
		}

		// Handle disconnect messages internally
		if msg.Type == MessageTypeDisconnect {
			reason := "Remote peer disconnected"
			if len(msg.Data) > 0 {
				reason = string(msg.Data)
			}
			p.logger.Info("Peer sent disconnect message", "peer", p.Address, "reason", reason)
			return
		}

		// Dispatch message to callback if set
		p.mutex.RLock()
		callback := p.onReceive
		p.mutex.RUnlock()

		if callback != nil {
			callback(p, msg)
		}
	}
}

// writeLoop continuously sends queued messages to the peer
func (p *Peer) writeLoop() {
	defer p.wg.Done()
	defer p.conn.Close()

	pingTicker := time.NewTicker(PingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case msg := <-p.outgoing:
			// Serialize message
			data, err := msg.Serialize()
			if err != nil {
				p.logger.Debug("Failed to serialize message", "error", err)
				continue
			}

			// Write message length
			p.conn.SetWriteDeadline(time.Now().Add(ConnectionTimeout))
			err = binary.Write(p.writer, binary.BigEndian, uint32(len(data)))
			if err != nil {
				p.logger.Debug("Failed to write message length", "error", err)
				return
			}

			// Write message data
			_, err = p.writer.Write(data)
			if err != nil {
				p.logger.Debug("Failed to write message data", "error", err)
				return
			}

			// Flush writer
			err = p.writer.Flush()
			if err != nil {
				p.logger.Debug("Failed to flush writer", "error", err)
				return
			}
		case <-pingTicker.C:
			// Send ping message
			p.sendPing()
		}
	}
}

// handlePing responds to ping messages with pong
func (p *Peer) handlePing(pingMsg *Message) {
	// Create pong message with same data
	msg, err := NewMessage(MessageTypePong, pingMsg.Data, p.PrivateKey)
	if err != nil {
		p.logger.Debug("Failed to create pong message", "error", err)
		return
	}

	// Send pong
	err = p.SendMessage(msg)
	if err != nil {
		p.logger.Debug("Failed to send pong message", "error", err)
	}
}

// sendPing sends a ping message to keep the connection alive
func (p *Peer) sendPing() {
	// Create ping message with current timestamp as data
	timestamp := time.Now().UnixNano()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(timestamp))

	msg, err := NewMessage(MessageTypePing, data, p.PrivateKey)
	if err != nil {
		p.logger.Debug("Failed to create ping message", "error", err)
		return
	}

	// Send ping
	err = p.SendMessage(msg)
	if err != nil {
		p.logger.Debug("Failed to send ping message", "error", err)
	}
}

// Disconnect closes the connection to the peer
func (p *Peer) Disconnect(reason string) {
	p.mutex.Lock()
	if p.closed {
		p.mutex.Unlock()
		return
	}
	p.closed = true
	p.setState(PeerStateDisconnecting)
	p.mutex.Unlock()

	// Try to send disconnect message if we're still connected
	if p.conn != nil {
		msg, err := NewMessage(MessageTypeDisconnect, []byte(reason), p.PrivateKey)
		if err == nil {
			// Convert to bytes
			data, err := msg.Serialize()
			if err == nil {
				// We write directly instead of using the channel to ensure it gets sent
				p.conn.SetWriteDeadline(time.Now().Add(DisconnectTimeout))
				binary.Write(p.writer, binary.BigEndian, uint32(len(data)))
				p.writer.Write(data)
				p.writer.Flush()
			}
		}
	}

	// Close channel to signal read/write loops to exit
	close(p.closeCh)

	// Wait for read/write loops to exit
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		// Loops exited
	case <-time.After(DisconnectTimeout):
		// Timed out
	}

	// Close connection if still open
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}

	p.setState(PeerStateDisconnected)
	p.logger.Info("Disconnected from peer", "address", p.Address, "reason", reason)
}

// String returns a string representation of the peer
func (p *Peer) String() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	nodeID := "unknown"
	if p.NodeID != "" {
		nodeID = p.NodeID
	}

	return fmt.Sprintf("Peer{NodeID: %s, Address: %s, State: %s, Validator: %v}",
		nodeID, p.Address, p.state.String(), p.IsValidator)
}

// State returns the current state of the peer
func (p *Peer) State() PeerState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.state
}

// setState updates the peer state with proper locking
func (p *Peer) setState(state PeerState) {
	// Caller should hold the lock
	oldState := p.state
	p.state = state

	if oldState != state {
		p.logger.Debug("Peer state changed",
			"peer", p.Address,
			"from", oldState.String(),
			"to", state.String())
	}
}

// LastSeen returns the timestamp of the last message received from the peer
func (p *Peer) LastSeen() time.Time {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.lastSeen
}

// IsConnected returns whether the peer is connected
func (p *Peer) IsConnected() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.state == PeerStateConnected
}

// String returns a string representation of the peer state
func (s PeerState) String() string {
	switch s {
	case PeerStateInit:
		return "Init"
	case PeerStateConnecting:
		return "Connecting"
	case PeerStateHandshaking:
		return "Handshaking"
	case PeerStateConnected:
		return "Connected"
	case PeerStateDisconnecting:
		return "Disconnecting"
	case PeerStateDisconnected:
		return "Disconnected"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}
