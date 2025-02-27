package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SecureSession represents a secure communication session
type SecureSession struct {
	SessionID          string            `json:"sessionId"`
	SessionType        string            `json:"sessionType"` // "SIP", "SRTP", "MQTT", etc.
	InitiatorOrgID     string            `json:"initiatorOrgId"`
	RecipientOrgID     string            `json:"recipientOrgId"`
	StartTime          int64             `json:"startTime"`
	EndTime            int64             `json:"endTime,omitempty"`
	KeyRotationCount   int               `json:"keyRotationCount"`
	QuantumAlgorithms  []string          `json:"quantumAlgorithms"` // "Falcon", "Kyber", etc.
	SecurityLevel      string            `json:"securityLevel"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	Status             string            `json:"status"` // "active", "completed", "terminated", "compromised"
	LastUpdated        int64             `json:"lastUpdated"`
	TransactionHistory []string          `json:"transactionHistory,omitempty"`
}

// AsteriskConfig represents a secure Asterisk configuration
type AsteriskConfig struct {
	OrgID           string              `json:"orgId"`
	Version         string              `json:"version"`
	LastUpdated     int64               `json:"lastUpdated"`
	QuantumEnabled  bool                `json:"quantumEnabled"`
	KeyTypes        []string            `json:"keyTypes"`
	KeyStore        string              `json:"keyStore"`
	RefreshInterval int                 `json:"refreshInterval"`
	SIPSettings     map[string]string   `json:"sipSettings,omitempty"`
	PeerConnections []PeerConfiguration `json:"peerConnections,omitempty"`
}

// PeerConfiguration represents a connection to another org's Asterisk server
type PeerConfiguration struct {
	PeerOrgID       string            `json:"peerOrgId"`
	Hostname        string            `json:"hostname"`
	Port            int               `json:"port"`
	TransportType   string            `json:"transportType"` // "UDP", "TCP", "TLS"
	QuantumEnabled  bool              `json:"quantumEnabled"`
	TrustLevel      string            `json:"trustLevel"` // "full", "limited", "untrusted"
	ConnectionState string            `json:"connectionState"`
	LastConnected   int64             `json:"lastConnected,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// QuantumCommunicationsContract manages quantum-secured communications
type QuantumCommunicationsContract struct {
	contractapi.Contract
}

// Initialize sets up the initial state
func (qcc *QuantumCommunicationsContract) Initialize(ctx contractapi.TransactionContextInterface) error {
	// Check if already initialized
	initialized, err := ctx.GetStub().GetState("initialized")
	if err != nil {
		return fmt.Errorf("failed to check initialization status: %v", err)
	}
	if initialized != nil {
		return nil
	}

	// Set initialization flag
	err = ctx.GetStub().PutState("initialized", []byte("true"))
	if err != nil {
		return fmt.Errorf("failed to set initialization flag: %v", err)
	}

	return nil
}

// RegisterAsteriskConfig stores Asterisk configuration for an organization
func (qcc *QuantumCommunicationsContract) RegisterAsteriskConfig(
	ctx contractapi.TransactionContextInterface,
	orgID string,
	configJSON string,
) error {
	// Validate inputs
	if orgID == "" {
		return fmt.Errorf("organization ID cannot be empty")
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return err
	}

	// Ensure only authorized organizations can register their own config
	if orgID != clientOrgID {
		return fmt.Errorf("unauthorized: organization %s cannot register config for %s", clientOrgID, orgID)
	}

	// Parse config JSON
	var config AsteriskConfig
	err = json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		return fmt.Errorf("failed to parse config JSON: %v", err)
	}

	// Set consistent values
	config.OrgID = orgID
	config.LastUpdated = ctx.GetStub().GetTxTimestamp().Seconds

	// Marshal config
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Store config in state
	key := fmt.Sprintf("asterisk-config-%s", orgID)
	err = ctx.GetStub().PutState(key, configBytes)
	if err != nil {
		return fmt.Errorf("failed to store Asterisk config: %v", err)
	}

	return nil
}

// GetAsteriskConfig retrieves Asterisk configuration for an organization
func (qcc *QuantumCommunicationsContract) GetAsteriskConfig(
	ctx contractapi.TransactionContextInterface,
	orgID string,
) (*AsteriskConfig, error) {
	// Validate inputs
	if orgID == "" {
		return nil, fmt.Errorf("organization ID cannot be empty")
	}

	// Get config from state
	key := fmt.Sprintf("asterisk-config-%s", orgID)
	configBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read Asterisk config: %v", err)
	}
	if configBytes == nil {
		return nil, fmt.Errorf("Asterisk config for %s does not exist", orgID)
	}

	// Unmarshal config
	var config AsteriskConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return &config, nil
}

// RegisterPeerConnection registers a connection to another organization's Asterisk server
func (qcc *QuantumCommunicationsContract) RegisterPeerConnection(
	ctx contractapi.TransactionContextInterface,
	orgID string,
	peerOrgID string,
	peerConfigJSON string,
) error {
	// Validate inputs
	if orgID == "" || peerOrgID == "" {
		return fmt.Errorf("organization IDs cannot be empty")
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return err
	}

	// Ensure only authorized organizations can register their own connections
	if orgID != clientOrgID {
		return fmt.Errorf("unauthorized: organization %s cannot register connections for %s", clientOrgID, orgID)
	}

	// Get current Asterisk config
	key := fmt.Sprintf("asterisk-config-%s", orgID)
	configBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to read Asterisk config: %v", err)
	}
	if configBytes == nil {
		return fmt.Errorf("Asterisk config for %s does not exist", orgID)
	}

	// Unmarshal config
	var config AsteriskConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Parse peer config
	var peerConfig PeerConfiguration
	err = json.Unmarshal([]byte(peerConfigJSON), &peerConfig)
	if err != nil {
		return fmt.Errorf("failed to parse peer config JSON: %v", err)
	}

	// Set consistent values
	peerConfig.PeerOrgID = peerOrgID
	peerConfig.LastConnected = ctx.GetStub().GetTxTimestamp().Seconds

	// Update peer connections
	var updated bool
	for i, pc := range config.PeerConnections {
		if pc.PeerOrgID == peerOrgID {
			config.PeerConnections[i] = peerConfig
			updated = true
			break
		}
	}
	if !updated {
		config.PeerConnections = append(config.PeerConnections, peerConfig)
	}
	config.LastUpdated = ctx.GetStub().GetTxTimestamp().Seconds

	// Marshal updated config
	updatedConfigBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %v", err)
	}

	// Store updated config
	err = ctx.GetStub().PutState(key, updatedConfigBytes)
	if err != nil {
		return fmt.Errorf("failed to store updated config: %v", err)
	}

	return nil
}

// StartSecureSession initiates a new secure communication session
func (qcc *QuantumCommunicationsContract) StartSecureSession(
	ctx contractapi.TransactionContextInterface,
	sessionJSON string,
) (string, error) {
	// Parse session JSON
	var session SecureSession
	err := json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return "", fmt.Errorf("failed to parse session JSON: %v", err)
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return "", err
	}

	// Ensure only the initiator can start the session
	if session.InitiatorOrgID != clientOrgID {
		return "", fmt.Errorf("unauthorized: organization %s cannot initiate session for %s",
			clientOrgID, session.InitiatorOrgID)
	}

	// Generate session ID if not provided
	if session.SessionID == "" {
		session.SessionID = fmt.Sprintf("session-%s-%d", clientOrgID, ctx.GetStub().GetTxTimestamp().Seconds)
	}

	// Set consistent values
	session.StartTime = ctx.GetStub().GetTxTimestamp().Seconds
	session.LastUpdated = session.StartTime
	session.Status = "active"
	if session.KeyRotationCount == 0 {
		session.KeyRotationCount = 1 // Initial key rotation
	}
	session.TransactionHistory = []string{ctx.GetStub().GetTxID()}

	// Marshal session
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session: %v", err)
	}

	// Store session
	err = ctx.GetStub().PutState(session.SessionID, sessionBytes)
	if err != nil {
		return "", fmt.Errorf("failed to store session: %v", err)
	}

	// Create indices
	initiatorSessionKey, err := ctx.GetStub().CreateCompositeKey(
		"org~initiator~session",
		[]string{session.InitiatorOrgID, session.SessionID},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create initiator index: %v", err)
	}
	err = ctx.GetStub().PutState(initiatorSessionKey, []byte{0})
	if err != nil {
		return "", fmt.Errorf("failed to store initiator index: %v", err)
	}

	recipientSessionKey, err := ctx.GetStub().CreateCompositeKey(
		"org~recipient~session",
		[]string{session.RecipientOrgID, session.SessionID},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create recipient index: %v", err)
	}
	err = ctx.GetStub().PutState(recipientSessionKey, []byte{0})
	if err != nil {
		return "", fmt.Errorf("failed to store recipient index: %v", err)
	}

	return session.SessionID, nil
}

// UpdateSessionStatus updates the status of a secure session
func (qcc *QuantumCommunicationsContract) UpdateSessionStatus(
	ctx contractapi.TransactionContextInterface,
	sessionID string,
	newStatus string,
	metadata string,
) error {
	// Validate inputs
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if newStatus == "" {
		return fmt.Errorf("new status cannot be empty")
	}

	// Get session from state
	sessionBytes, err := ctx.GetStub().GetState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to read session: %v", err)
	}
	if sessionBytes == nil {
		return fmt.Errorf("session %s does not exist", sessionID)
	}

	// Unmarshal session
	var session SecureSession
	err = json.Unmarshal(sessionBytes, &session)
	if err != nil {
		return fmt.Errorf("failed to unmarshal session: %v", err)
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return err
	}

	// Ensure only participating organizations can update the session
	if session.InitiatorOrgID != clientOrgID && session.RecipientOrgID != clientOrgID {
		return fmt.Errorf("unauthorized: organization %s cannot update session between %s and %s",
			clientOrgID, session.InitiatorOrgID, session.RecipientOrgID)
	}

	// Update session
	session.Status = newStatus
	session.LastUpdated = ctx.GetStub().GetTxTimestamp().Seconds
	session.TransactionHistory = append(session.TransactionHistory, ctx.GetStub().GetTxID())

	// Handle completion
	if newStatus == "completed" || newStatus == "terminated" {
		session.EndTime = ctx.GetStub().GetTxTimestamp().Seconds
	}

	// Update metadata if provided
	if metadata != "" {
		var metadataMap map[string]string
		err = json.Unmarshal([]byte(metadata), &metadataMap)
		if err != nil {
			return fmt.Errorf("failed to parse metadata: %v", err)
		}
		// Create metadata map if it doesn't exist
		if session.Metadata == nil {
			session.Metadata = make(map[string]string)
		}
		// Update metadata fields
		for k, v := range metadataMap {
			session.Metadata[k] = v
		}
	}

	// Marshal updated session
	updatedSessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session: %v", err)
	}

	// Store updated session
	err = ctx.GetStub().PutState(sessionID, updatedSessionBytes)
	if err != nil {
		return fmt.Errorf("failed to store updated session: %v", err)
	}

	return nil
}

// RotateSessionKeys records a key rotation event for a session
func (qcc *QuantumCommunicationsContract) RotateSessionKeys(
	ctx contractapi.TransactionContextInterface,
	sessionID string,
) error {
	// Validate inputs
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Get session from state
	sessionBytes, err := ctx.GetStub().GetState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to read session: %v", err)
	}
	if sessionBytes == nil {
		return fmt.Errorf("session %s does not exist", sessionID)
	}

	// Unmarshal session
	var session SecureSession
	err = json.Unmarshal(sessionBytes, &session)
	if err != nil {
		return fmt.Errorf("failed to unmarshal session: %v", err)
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return err
	}

	// Ensure only participating organizations can rotate keys
	if session.InitiatorOrgID != clientOrgID && session.RecipientOrgID != clientOrgID {
		return fmt.Errorf("unauthorized: organization %s cannot rotate keys for session between %s and %s",
			clientOrgID, session.InitiatorOrgID, session.RecipientOrgID)
	}

	// Ensure session is active
	if session.Status != "active" {
		return fmt.Errorf("cannot rotate keys for %s session", session.Status)
	}

	// Update session
	session.KeyRotationCount++
	session.LastUpdated = ctx.GetStub().GetTxTimestamp().Seconds
	session.TransactionHistory = append(session.TransactionHistory, ctx.GetStub().GetTxID())

	// Marshal updated session
	updatedSessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session: %v", err)
	}

	// Store updated session
	err = ctx.GetStub().PutState(sessionID, updatedSessionBytes)
	if err != nil {
		return fmt.Errorf("failed to store updated session: %v", err)
	}

	return nil
}

// GetSecureSession retrieves a secure session by ID
func (qcc *QuantumCommunicationsContract) GetSecureSession(
	ctx contractapi.TransactionContextInterface,
	sessionID string,
) (*SecureSession, error) {
	// Validate inputs
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Get session from state
	sessionBytes, err := ctx.GetStub().GetState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to read session: %v", err)
	}
	if sessionBytes == nil {
		return nil, fmt.Errorf("session %s does not exist", sessionID)
	}

	// Unmarshal session
	var session SecureSession
	err = json.Unmarshal(sessionBytes, &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %v", err)
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return nil, err
	}

	// Ensure only participating organizations can view the session
	if session.InitiatorOrgID != clientOrgID && session.RecipientOrgID != clientOrgID {
		return nil, fmt.Errorf("unauthorized: organization %s cannot view session between %s and %s",
			clientOrgID, session.InitiatorOrgID, session.RecipientOrgID)
	}

	return &session, nil
}

// GetActiveSessions retrieves all active sessions for an organization
func (qcc *QuantumCommunicationsContract) GetActiveSessions(
	ctx contractapi.TransactionContextInterface,
	orgID string,
) ([]*SecureSession, error) {
	// Validate inputs
	if orgID == "" {
		return nil, fmt.Errorf("organization ID cannot be empty")
	}

	// Check caller organization
	clientOrgID, err := getClientOrgID(ctx)
	if err != nil {
		return nil, err
	}

	// Ensure organization can only view its own sessions
	if orgID != clientOrgID {
		return nil, fmt.Errorf("unauthorized: organization %s cannot view sessions for %s",
			clientOrgID, orgID)
	}

	// Get sessions where organization is initiator
	initiatorIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(
		"org~initiator~session",
		[]string{orgID},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get initiator sessions: %v", err)
	}
	defer initiatorIterator.Close()

	// Get sessions where organization is recipient
	recipientIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(
		"org~recipient~session",
		[]string{orgID},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get recipient sessions: %v", err)
	}
	defer recipientIterator.Close()

	// Collect active sessions
	var sessions []*SecureSession
	sessionIDs := make(map[string]bool) // To avoid duplicates

	// Process initiator sessions
	for initiatorIterator.HasNext() {
		queryResponse, err := initiatorIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate through initiator sessions: %v", err)
		}

		// Extract session ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		if len(compositeKeyParts) < 2 {
			continue
		}
		sessionID := compositeKeyParts[1]

		// Skip if already processed
		if sessionIDs[sessionID] {
			continue
		}
		sessionIDs[sessionID] = true

		// Get session details
		sessionBytes, err := ctx.GetStub().GetState(sessionID)
		if err != nil || sessionBytes == nil {
			continue
		}

		// Unmarshal session
		var session SecureSession
		err = json.Unmarshal(sessionBytes, &session)
		if err != nil {
			continue
		}

		// Add active sessions
		if session.Status == "active" {
			sessions = append(sessions, &session)
		}
	}

	// Process recipient sessions
	for recipientIterator.HasNext() {
		queryResponse, err := recipientIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate through recipient sessions: %v", err)
		}

		// Extract session ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}
		if len(compositeKeyParts) < 2 {
			continue
		}
		sessionID := compositeKeyParts[1]

		// Skip if already processed
		if sessionIDs[sessionID] {
			continue
		}
		sessionIDs[sessionID] = true

		// Get session details
		sessionBytes, err := ctx.GetStub().GetState(sessionID)
		if err != nil || sessionBytes == nil {
			continue
		}

		// Unmarshal session
		var session SecureSession
		err = json.Unmarshal(sessionBytes, &session)
		if err != nil {
			continue
		}

		// Add active sessions
		if session.Status == "active" {
			sessions = append(sessions, &session)
		}
	}

	return sessions, nil
}

// Helper function to get the organization ID of the client
func getClientOrgID(ctx contractapi.TransactionContextInterface) (string, error) {
	// Get client identity
	clientIdentity, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client identity: %v", err)
	}

	// Get MSP ID (organization ID)
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get client MSP ID: %v", err)
	}

	return mspID, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&QuantumCommunicationsContract{})
	if err != nil {
		fmt.Printf("Error creating quantum-communications chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting quantum-communications chaincode: %v\n", err)
	}
}