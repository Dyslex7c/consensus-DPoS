package network

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// PeerManagerConfig holds configuration for the peer manager
type PeerManagerConfig struct {
	// Network ID to use for this node
	NetworkID string
	// Listen address for incoming connections
	ListenAddress string
	// Seed peers to connect to
	PeerSeeds []string
	// Maximum number of peers to connect to
	MaxPeers int
	// NodeID for this node
	NodeID string
	// Whether this node is a validator
	IsValidator bool
	// Private key for this node
	PrivateKey ed25519.PrivateKey
}

// PeerManager handles P2P peer discovery and management
type PeerManager struct {
	config    PeerManagerConfig
	peers     map[string]*Peer // NodeID -> Peer
	peersByIP map[string]*Peer // IP:Port -> Peer
	listener  net.Listener
	logger    *utils.Logger
	running   bool
	mutex     sync.RWMutex
	closeCh   chan struct{}
	wg        sync.WaitGroup

	// Message handlers by type
	messageHandlers map[MessageType]func(*Peer, *Message)

	// Callbacks for client notification
	onPeerConnected    func(*Peer)
	onPeerDisconnected func(*Peer)
	onBlockReceived    func(*Peer, *Message)
	onTxReceived       func(*Peer, *Message)
}

// NewPeerManager creates a new peer manager
func NewPeerManager(cfg PeerManagerConfig, logger *utils.Logger) *PeerManager {
	pm := &PeerManager{
		config:          cfg,
		peers:           make(map[string]*Peer),
		peersByIP:       make(map[string]*Peer),
		logger:          logger,
		closeCh:         make(chan struct{}),
		messageHandlers: make(map[MessageType]func(*Peer, *Message)),
	}

	// Register default message handlers
	pm.registerDefaultHandlers()

	return pm
}

// registerDefaultHandlers sets up the default message handlers
func (pm *PeerManager) registerDefaultHandlers() {
	pm.messageHandlers[MessageTypePing] = pm.handlePingMessage
	pm.messageHandlers[MessageTypePong] = pm.handlePongMessage
	pm.messageHandlers[MessageTypeGetPeers] = pm.handleGetPeersMessage
	pm.messageHandlers[MessageTypePeers] = pm.handlePeersMessage
	pm.messageHandlers[MessageTypeDisconnect] = pm.handleDisconnectMessage
}

// RegisterMessageHandler registers a handler for a specific message type
func (pm *PeerManager) RegisterMessageHandler(msgType MessageType, handler func(*Peer, *Message)) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.messageHandlers[msgType] = handler
}

// SetCallbacks sets callback functions for the peer manager
func (pm *PeerManager) SetCallbacks(
	onPeerConnected func(*Peer),
	onPeerDisconnected func(*Peer),
	onBlockReceived func(*Peer, *Message),
	onTxReceived func(*Peer, *Message),
) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.onPeerConnected = onPeerConnected
	pm.onPeerDisconnected = onPeerDisconnected
	pm.onBlockReceived = onBlockReceived
	pm.onTxReceived = onTxReceived
}

// Start begins listening for peers and initiates connections to seed peers
func (pm *PeerManager) Start() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return fmt.Errorf("peer manager already running")
	}

	// Start listening for incoming connections
	listener, err := net.Listen("tcp", pm.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", pm.config.ListenAddress, err)
	}
	pm.listener = listener
	pm.running = true

	// Start accepting connections
	pm.wg.Add(1)
	go pm.acceptConnections()

	// Connect to seed peers
	for _, seedAddr := range pm.config.PeerSeeds {
		pm.wg.Add(1)
		go func(addr string) {
			defer pm.wg.Done()
			pm.connectToPeer(addr)
		}(seedAddr)
	}

	// Start periodic peer discovery
	pm.wg.Add(1)
	go pm.peerDiscoveryLoop()

	pm.logger.Info("PeerManager started. Listening on %s", "address", pm.config.ListenAddress)
	return nil
}

// Stop shuts down the peer manager and all connections
func (pm *PeerManager) Stop() {
	pm.mutex.Lock()
	if !pm.running {
		pm.mutex.Unlock()
		return
	}
	pm.running = false
	pm.mutex.Unlock()

	// Signal all goroutines to stop
	close(pm.closeCh)

	// Close the listener
	if pm.listener != nil {
		pm.listener.Close()
	}

	// Disconnect all peers
	pm.mutex.RLock()
	for _, peer := range pm.peers {
		peer.Disconnect("node shutting down")
	}
	pm.mutex.RUnlock()

	// Wait for all goroutines to finish
	pm.wg.Wait()
	pm.logger.Info("PeerManager stopped")
}

// acceptConnections handles incoming connection requests
func (pm *PeerManager) acceptConnections() {
	defer pm.wg.Done()

	for {
		conn, err := pm.listener.Accept()
		if err != nil {
			select {
			case <-pm.closeCh:
				return // Manager is shutting down
			default:
				pm.logger.Error("Error accepting connection: %v", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		pm.wg.Add(1)
		go func() {
			defer pm.wg.Done()
			pm.handleIncomingConnection(conn)
		}()
	}
}

// NewPeerIncoming creates a new incoming peer from an accepted connection
func NewPeerIncoming(conn net.Conn, networkID string, nodeID string, privateKey ed25519.PrivateKey, logger *utils.Logger) (*Peer, error) {
	peer := &Peer{
		conn:       conn,
		Address:    conn.RemoteAddr().String(),
		state:      PeerStateHandshaking,
		NodeID:     nodeID,
		PrivateKey: privateKey,
		outgoing:   make(chan *Message, MaxPendingMessages),
		closeCh:    make(chan struct{}),
		lastSeen:   time.Now(),
		logger:     logger,
	}

	peer.reader = bufio.NewReader(conn)
	peer.writer = bufio.NewWriter(conn)

	return peer, nil
}

// NewPeerOutgoing creates a new outgoing peer for a connection we initiated
func NewPeerOutgoing(conn net.Conn, address string, networkID string, nodeID string, privateKey ed25519.PrivateKey, logger *utils.Logger) (*Peer, error) {
	peer := &Peer{
		conn:       conn,
		Address:    address,
		state:      PeerStateHandshaking,
		NodeID:     nodeID,
		PrivateKey: privateKey,
		outgoing:   make(chan *Message, MaxPendingMessages),
		closeCh:    make(chan struct{}),
		lastSeen:   time.Now(),
		logger:     logger,
	}

	peer.reader = bufio.NewReader(conn)
	peer.writer = bufio.NewWriter(conn)

	return peer, nil
}

// handleIncomingConnection processes a new incoming connection
func (pm *PeerManager) handleIncomingConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	pm.logger.Debug("Incoming connection from %s", "address", remoteAddr)

	// Create a new peer with the connection
	peer, err := NewPeerIncoming(conn, pm.config.NetworkID, pm.config.NodeID, pm.config.PrivateKey, pm.logger)
	if err != nil {
		pm.logger.Error("Failed to create peer for %s: %v", "address", remoteAddr, "error", err)
		conn.Close()
		return
	}

	// Register the peer if handshake succeeds
	if err := pm.registerPeer(peer); err != nil {
		pm.logger.Error("Failed to register peer %s: %v", "address", remoteAddr, "error", err)
		peer.Disconnect(fmt.Sprintf("registration failed: %v", err))
		return
	}

	// Start the peer processing loop
	peer.Start(pm.handlePeerMessage)
}

// connectToPeer attempts to establish a connection to a peer
func (pm *PeerManager) connectToPeer(address string) error {
	pm.mutex.RLock()
	if _, exists := pm.peersByIP[address]; exists {
		pm.mutex.RUnlock()
		return fmt.Errorf("already connected to %s", address)
	}
	pm.mutex.RUnlock()

	pm.logger.Debug("Connecting to peer %s", "address", address)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	// Create a new outgoing peer
	peer, err := NewPeerOutgoing(conn, address, pm.config.NetworkID, pm.config.NodeID, pm.config.PrivateKey, pm.logger)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create peer for %s: %v", address, err)
	}

	// Register the peer if handshake succeeds
	if err := pm.registerPeer(peer); err != nil {
		peer.Disconnect(fmt.Sprintf("registration failed: %v", err))
		return fmt.Errorf("failed to register peer %s: %v", address, err)
	}

	// Start the peer processing loop
	peer.Start(pm.handlePeerMessage)
	return nil
}

// registerPeer adds a peer to the peer manager's map
func (pm *PeerManager) registerPeer(peer *Peer) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if we already have this peer by address
	if existingPeer, exists := pm.peersByIP[peer.Address]; exists {
		return fmt.Errorf("already connected to peer %s", existingPeer.Address)
	}

	// Check if we're at max peers
	if len(pm.peers) >= pm.config.MaxPeers {
		return fmt.Errorf("maximum number of peers reached (%d)", pm.config.MaxPeers)
	}

	// Perform handshake
	err := peer.Handshake(pm.config.NetworkID, pm.config.NodeID, pm.config.ListenAddress, pm.config.IsValidator, pm.config.PrivateKey)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Add peer to maps
	pm.peersByIP[peer.Address] = peer

	// We'll add to pm.peers once we have the NodeID (after handshake completes)

	pm.logger.Info("Registered new peer", "address", peer.Address)
	return nil
}

// unregisterPeer removes a peer from the peer manager's maps
func (pm *PeerManager) unregisterPeer(peer *Peer) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Remove from maps
	delete(pm.peersByIP, peer.Address)
	if peer.NodeID != "" {
		delete(pm.peers, peer.NodeID)
	}

	pm.logger.Info("Unregistered peer", "address", peer.Address, "nodeID", peer.NodeID)

	// Notify client if callback is set
	if pm.onPeerDisconnected != nil && peer.NodeID != "" {
		pm.onPeerDisconnected(peer)
	}
}

// handlePeerMessage processes a message received from a peer
func (pm *PeerManager) handlePeerMessage(peer *Peer, msg *Message) {
	// Check if we should complete the handshake
	if msg.Type == MessageTypeHandshake {
		pm.handleHandshakeMessage(peer, msg)
		return
	}

	// Ignore messages from peers that haven't completed handshake
	if peer.State() != PeerStateConnected {
		pm.logger.Warn("Received message from peer before handshake completion",
			"address", peer.Address,
			"msgType", msg.Type)
		return
	}

	// Find the appropriate handler for this message type
	pm.mutex.RLock()
	handler, exists := pm.messageHandlers[msg.Type]
	pm.mutex.RUnlock()

	if exists {
		handler(peer, msg)
	} else {
		pm.logger.Warn("Received unknown message type",
			"type", msg.Type,
			"peer", peer.Address)
	}
}

// handleHandshakeMessage processes a handshake message from a peer
func (pm *PeerManager) handleHandshakeMessage(peer *Peer, msg *Message) {
	// Process the handshake
	err := peer.HandleHandshake(msg, pm.config.NetworkID)
	if err != nil {
		pm.logger.Error("Handshake failed", "error", err, "peer", peer.Address)
		peer.Disconnect(fmt.Sprintf("handshake failed: %v", err))
		return
	}

	// Now that we have the NodeID, check if we already know this peer
	pm.mutex.Lock()
	if _, exists := pm.peers[peer.NodeID]; exists {
		pm.mutex.Unlock()
		pm.logger.Warn("Duplicate peer connection", "nodeID", peer.NodeID, "address", peer.Address)
		peer.Disconnect("duplicate connection")
		return
	}

	// Add to peers map now that we have the NodeID
	pm.peers[peer.NodeID] = peer
	pm.mutex.Unlock()

	// Notify client if callback is set
	if pm.onPeerConnected != nil {
		pm.onPeerConnected(peer)
	}

	// Send get peers message to start peer discovery
	pm.sendGetPeersMessage(peer)
}

// peerDiscoveryLoop periodically asks peers for their known peers
func (pm *PeerManager) peerDiscoveryLoop() {
	defer pm.wg.Done()

	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.closeCh:
			return
		case <-ticker.C:
			pm.discoverPeers()
		}
	}
}

// discoverPeers requests peer information from all connected peers
func (pm *PeerManager) discoverPeers() {
	pm.mutex.RLock()
	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		if peer.IsConnected() {
			peers = append(peers, peer)
		}
	}
	pm.mutex.RUnlock()

	for _, peer := range peers {
		pm.sendGetPeersMessage(peer)
	}
}

// sendGetPeersMessage sends a GetPeers message to a peer
func (pm *PeerManager) sendGetPeersMessage(peer *Peer) {
	msg, err := NewMessage(MessageTypeGetPeers, nil, pm.config.PrivateKey)
	if err != nil {
		pm.logger.Error("Failed to create GetPeers message", "error", err)
		return
	}

	err = peer.SendMessage(msg)
	if err != nil {
		pm.logger.Error("Failed to send GetPeers message", "error", err, "peer", peer.Address)
	}
}

// Start starts the peer processing loop
func (p *Peer) Start(msgHandler func(*Peer, *Message)) {
	p.mutex.Lock()
	p.onReceive = msgHandler
	p.mutex.Unlock()

	// Start the read and write loops
	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()
}

// GetPeers returns a list of all connected peers
func (pm *PeerManager) GetPeers() []*Peer {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		peers = append(peers, peer)
	}

	return peers
}

// Broadcast sends a message to all connected peers
func (pm *PeerManager) Broadcast(msg *Message) {
	pm.mutex.RLock()
	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		if peer.IsConnected() {
			peers = append(peers, peer)
		}
	}
	pm.mutex.RUnlock()

	for _, peer := range peers {
		err := peer.SendMessage(msg)
		if err != nil {
			pm.logger.Debug("Failed to broadcast message to peer",
				"peer", peer.Address,
				"error", err)
		}
	}
}

// BroadcastToValidators sends a message only to validator peers
func (pm *PeerManager) BroadcastToValidators(msg *Message) {
	pm.mutex.RLock()
	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		if peer.IsValidator && peer.IsConnected() {
			peers = append(peers, peer)
		}
	}
	pm.mutex.RUnlock()

	for _, peer := range peers {
		err := peer.SendMessage(msg)
		if err != nil {
			pm.logger.Debug("Failed to broadcast message to validator peer",
				"peer", peer.Address,
				"error", err)
		}
	}
}

// handlePingMessage processes a ping message from a peer
func (pm *PeerManager) handlePingMessage(peer *Peer, msg *Message) {
	// Peer already replied with a Pong in the readLoop
	// Nothing more to do here
}

// handlePongMessage processes a pong message from a peer
func (pm *PeerManager) handlePongMessage(peer *Peer, msg *Message) {
	// Already processed in readLoop (lastSeen updated)
	// Nothing more to do here
}

// handleGetPeersMessage processes a GetPeers message from a peer
func (pm *PeerManager) handleGetPeersMessage(peer *Peer, msg *Message) {
	pm.mutex.RLock()
	// Create a list of peer infos, excluding the requesting peer
	peerInfos := make([]PeerInfo, 0, len(pm.peers)-1)
	for id, p := range pm.peers {
		if id != peer.NodeID && p.IsConnected() {
			peerInfos = append(peerInfos, PeerInfo{
				NodeID:      p.NodeID,
				Address:     p.ListenAddr,
				IsValidator: p.IsValidator,
			})
		}
	}
	pm.mutex.RUnlock()

	// Create and send the response
	peerList := &PeerList{
		Peers: peerInfos,
	}

	data, err := EncodePeerList(peerList)
	if err != nil {
		pm.logger.Error("Failed to encode peer list", "error", err)
		return
	}

	response, err := NewMessage(MessageTypePeers, data, pm.config.PrivateKey)
	if err != nil {
		pm.logger.Error("Failed to create Peers message", "error", err)
		return
	}

	err = peer.SendMessage(response)
	if err != nil {
		pm.logger.Error("Failed to send Peers message", "error", err, "peer", peer.Address)
	}
}

// handlePeersMessage processes a Peers message from a peer
func (pm *PeerManager) handlePeersMessage(peer *Peer, msg *Message) {
	peerList, err := DecodePeerList(msg.Data)
	if err != nil {
		pm.logger.Error("Failed to decode peer list", "error", err, "peer", peer.Address)
		return
	}

	for _, peerInfo := range peerList.Peers {
		// Skip ourselves
		if peerInfo.NodeID == pm.config.NodeID {
			continue
		}

		// Skip already connected peers
		pm.mutex.RLock()
		_, exists := pm.peers[peerInfo.NodeID]
		pm.mutex.RUnlock()
		if exists {
			continue
		}

		// Connect to the new peer if we're not at max peers
		pm.mutex.RLock()
		currentPeers := len(pm.peers)
		pm.mutex.RUnlock()

		if currentPeers < pm.config.MaxPeers {
			// Try to connect in a separate goroutine
			go func(addr string) {
				err := pm.connectToPeer(addr)
				if err != nil {
					pm.logger.Debug("Failed to connect to discovered peer", "address", addr, "error", err)
				}
			}(peerInfo.Address)
		}
	}
}

// handleDisconnectMessage processes a Disconnect message from a peer
func (pm *PeerManager) handleDisconnectMessage(peer *Peer, msg *Message) {
	reason := "no reason provided"
	if len(msg.Data) > 0 {
		reason = string(msg.Data)
	}

	pm.logger.Info("Peer disconnected",
		"peer", peer.Address,
		"nodeID", peer.NodeID,
		"reason", reason)

	// The peer's readLoop will handle disconnection
}

// GetPeerByID returns a peer by its node ID
func (pm *PeerManager) GetPeerByID(nodeID string) *Peer {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.peers[nodeID]
}

// GetPeerByAddress returns a peer by its address
func (pm *PeerManager) GetPeerByAddress(address string) *Peer {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.peersByIP[address]
}

// PeerCount returns the number of connected peers
func (pm *PeerManager) PeerCount() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return len(pm.peers)
}

// ConnectToPeerByAddress attempts to connect to a peer by address
func (pm *PeerManager) ConnectToPeerByAddress(address string) error {
	// Check if we're already connected to this peer
	pm.mutex.RLock()
	_, exists := pm.peersByIP[address]
	pm.mutex.RUnlock()

	if exists {
		return fmt.Errorf("already connected to peer %s", address)
	}

	return pm.connectToPeer(address)
}

// DisconnectPeer disconnects a peer by its node ID
func (pm *PeerManager) DisconnectPeer(nodeID string, reason string) error {
	pm.mutex.RLock()
	peer, exists := pm.peers[nodeID]
	pm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("peer %s not found", nodeID)
	}

	peer.Disconnect(reason)
	pm.unregisterPeer(peer)
	return nil
}
