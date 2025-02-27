package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// HederaTransaction represents a transaction on the Hedera network
type HederaTransaction struct {
	TransactionID      string            `json:"transactionId"`
	TopicID            string            `json:"topicId,omitempty"`
	SequenceNumber     string            `json:"sequenceNumber,omitempty"`
	ConsensusTimestamp int64             `json:"consensusTimestamp"`
	DataHash           string            `json:"dataHash,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	SubmittedBy        string            `json:"submittedBy"`
	CreatedAt          int64             `json:"createdAt"`
}

// QuantumHederaContract is the smart contract for quantum-secured Hedera integration
type QuantumHederaContract struct {
	contractapi.Contract
}

// Initialize sets up the initial state for the chaincode
func (qhc *QuantumHederaContract) Initialize(ctx contractapi.TransactionContextInterface) error {
	// Check if the ledger is already initialized
	initialized, err := ctx.GetStub().GetState("initialized")
	if err != nil {
		return fmt.Errorf("failed to check initialization status: %v", err)
	}

	// If already initialized, return early
	if initialized != nil {
		return nil
	}

	// Set initialization flag
	err = ctx.GetStub().PutState("initialized", []byte("true"))
	if err != nil {
		return fmt.Errorf("failed to set initialization flag: %v", err)
	}

	// Create initial metadata structure
	metadata := map[string]string{
		"name":        "Quantum-Hedera Integration",
		"version":     "1.0.0",
		"description": "Chaincode for secure integration between Hyperledger Fabric and Hedera Hashgraph",
		"initialized": time.Now().UTC().Format(time.RFC3339),
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	err = ctx.GetStub().PutState("metadata", metadataJSON)
	if err != nil {
		return fmt.Errorf("failed to store metadata: %v", err)
	}

	return nil
}

// StoreHederaReference stores a reference to a Hedera transaction
func (qhc *QuantumHederaContract) StoreHederaReference(
	ctx contractapi.TransactionContextInterface,
	transactionID string,
	referenceDataJSON string,
	submittedBy string,
) error {
	// Validate inputs
	if transactionID == "" {
		return fmt.Errorf("transaction ID cannot be empty")
	}

	// Check if transaction already exists
	existing, err := ctx.GetStub().GetState(transactionID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("transaction with ID %s already exists", transactionID)
	}

	// Parse reference data
	var referenceData map[string]interface{}
	err = json.Unmarshal([]byte(referenceDataJSON), &referenceData)
	if err != nil {
		return fmt.Errorf("failed to parse reference data: %v", err)
	}

	// Extract values from reference data
	topicID, _ := referenceData["topicId"].(string)
	sequenceNumber, _ := referenceData["sequenceNumber"].(string)
	dataHash, _ := referenceData["dataHash"].(string)

	// Build metadata map
	metadata := make(map[string]string)
	for k, v := range referenceData {
		if str, ok := v.(string); ok {
			metadata[k] = str
		}
	}

	// Create transaction object
	transaction := HederaTransaction{
		TransactionID:      transactionID,
		TopicID:            topicID,
		SequenceNumber:     sequenceNumber,
		ConsensusTimestamp: getTimestampFromReferenceData(referenceData),
		DataHash:           dataHash,
		Metadata:           metadata,
		SubmittedBy:        submittedBy,
		CreatedAt:          ctx.GetStub().GetTxTimestamp().Seconds,
	}

	// Marshal to JSON
	transactionJSON, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}

	// Store on the ledger
	err = ctx.GetStub().PutState(transactionID, transactionJSON)
	if err != nil {
		return fmt.Errorf("failed to store transaction: %v", err)
	}

	// Create composite key for organization index
	orgTransactionKey, err := ctx.GetStub().CreateCompositeKey("org~transaction", []string{submittedBy, transactionID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	// Store empty value for the index
	err = ctx.GetStub().PutState(orgTransactionKey, []byte{0})
	if err != nil {
		return fmt.Errorf("failed to store organization index: %v", err)
	}

	// Create composite key for topic index if topicID exists
	if topicID != "" {
		topicTransactionKey, err := ctx.GetStub().CreateCompositeKey("topic~transaction", []string{topicID, transactionID})
		if err != nil {
			return fmt.Errorf("failed to create topic composite key: %v", err)
		}

		// Store empty value for the index
		err = ctx.GetStub().PutState(topicTransactionKey, []byte{0})
		if err != nil {
			return fmt.Errorf("failed to store topic index: %v", err)
		}
	}

	return nil
}

// GetHederaReference retrieves a Hedera transaction reference
func (qhc *QuantumHederaContract) GetHederaReference(
	ctx contractapi.TransactionContextInterface,
	transactionID string,
) (*HederaTransaction, error) {
	// Validate input
	if transactionID == "" {
		return nil, fmt.Errorf("transaction ID cannot be empty")
	}

	// Get transaction from world state
	transactionJSON, err := ctx.GetStub().GetState(transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if transactionJSON == nil {
		return nil, fmt.Errorf("transaction with ID %s does not exist", transactionID)
	}

	// Unmarshal transaction
	var transaction HederaTransaction
	err = json.Unmarshal(transactionJSON, &transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction: %v", err)
	}

	return &transaction, nil
}

// QueryHederaReferencesByOrg queries transactions submitted by a specific organization
func (qhc *QuantumHederaContract) QueryHederaReferencesByOrg(
	ctx contractapi.TransactionContextInterface,
	orgID string,
) ([]*HederaTransaction, error) {
	// Validate input
	if orgID == "" {
		return nil, fmt.Errorf("organization ID cannot be empty")
	}

	// Get iterator for composite keys
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey("org~transaction", []string{orgID})
	if err != nil {
		return nil, fmt.Errorf("failed to get state by partial composite key: %v", err)
	}
	defer iterator.Close()

	// Collect transactions
	var transactions []*HederaTransaction
	for iterator.HasNext() {
		queryResponse, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate through results: %v", err)
		}

		// Extract transaction ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}

		if len(compositeKeyParts) < 2 {
			continue // Skip if invalid composite key
		}

		transactionID := compositeKeyParts[1]

		// Get transaction details
		transactionJSON, err := ctx.GetStub().GetState(transactionID)
		if err != nil {
			return nil, fmt.Errorf("failed to read transaction: %v", err)
		}

		if transactionJSON == nil {
			continue // Skip if transaction doesn't exist (should not happen)
		}

		// Unmarshal transaction
		var transaction HederaTransaction
		err = json.Unmarshal(transactionJSON, &transaction)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction: %v", err)
		}

		// Add to result
		transactions = append(transactions, &transaction)
	}

	return transactions, nil
}

// QueryHederaReferencesByTopic queries transactions for a specific Hedera topic
func (qhc *QuantumHederaContract) QueryHederaReferencesByTopic(
	ctx contractapi.TransactionContextInterface,
	topicID string,
) ([]*HederaTransaction, error) {
	// Validate input
	if topicID == "" {
		return nil, fmt.Errorf("topic ID cannot be empty")
	}

	// Get iterator for composite keys
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey("topic~transaction", []string{topicID})
	if err != nil {
		return nil, fmt.Errorf("failed to get state by partial composite key: %v", err)
	}
	defer iterator.Close()

	// Collect transactions
	var transactions []*HederaTransaction
	for iterator.HasNext() {
		queryResponse, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate through results: %v", err)
		}

		// Extract transaction ID from composite key
		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}

		if len(compositeKeyParts) < 2 {
			continue // Skip if invalid composite key
		}

		transactionID := compositeKeyParts[1]

		// Get transaction details
		transactionJSON, err := ctx.GetStub().GetState(transactionID)
		if err != nil {
			return nil, fmt.Errorf("failed to read transaction: %v", err)
		}

		if transactionJSON == nil {
			continue // Skip if transaction doesn't exist (should not happen)
		}

		// Unmarshal transaction
		var transaction HederaTransaction
		err = json.Unmarshal(transactionJSON, &transaction)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction: %v", err)
		}

		// Add to result
		transactions = append(transactions, &transaction)
	}

	return transactions, nil
}

// QueryHederaReferencesByTimeRange queries transactions within a time range
func (qhc *QuantumHederaContract) QueryHederaReferencesByTimeRange(
	ctx contractapi.TransactionContextInterface,
	startTime int64,
	endTime int64,
) ([]*HederaTransaction, error) {
	// Validate input
	if startTime < 0 || endTime < 0 {
		return nil, fmt.Errorf("time values cannot be negative")
	}
	if endTime > 0 && startTime > endTime {
		return nil, fmt.Errorf("start time cannot be greater than end time")
	}

	// Use rich query if CouchDB is enabled
	queryString := fmt.Sprintf(`{
		"selector": {
			"consensusTimestamp": {
				"$gte": %d
			},
			"docType": "HederaTransaction"
		}
	}`, startTime)

	if endTime > 0 {
		queryString = fmt.Sprintf(`{
			"selector": {
				"consensusTimestamp": {
					"$gte": %d,
					"$lte": %d
				},
				"docType": "HederaTransaction"
			}
		}`, startTime, endTime)
	}

	iterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to execute rich query: %v", err)
	}
	defer iterator.Close()

	// Collect transactions
	var transactions []*HederaTransaction
	for iterator.HasNext() {
		queryResponse, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate through results: %v", err)
		}

		// Unmarshal transaction
		var transaction HederaTransaction
		err = json.Unmarshal(queryResponse.Value, &transaction)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction: %v", err)
		}

		// Add to result
		transactions = append(transactions, &transaction)
	}

	return transactions, nil
}

// Helper function to extract timestamp from reference data
func getTimestampFromReferenceData(data map[string]interface{}) int64 {
	// Try to get consensusTimestamp as string first
	if tsStr, ok := data["consensusTimestamp"].(string); ok {
		// Try to parse RFC3339 format
		if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			return t.Unix()
		}

		// Try to parse Unix timestamp format
		if ts, err := fmt.Sscanf(tsStr, "%d", new(int64)); err == nil && ts > 0 {
			return int64(ts)
		}
	}

	// Try to get consensusTimestamp as number
	if ts, ok := data["consensusTimestamp"].(float64); ok {
		return int64(ts)
	}

	// Fall back to current time
	return time.Now().Unix()
}

// Main function starts the chaincode
func main() {
	chaincode, err := contractapi.NewChaincode(&QuantumHederaContract{})
	if err != nil {
		fmt.Printf("Error creating quantum-hedera chaincode: %v\n", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting quantum-hedera chaincode: %v\n", err)
	}
}