#!/bin/bash

# Create target directory
mkdir -p crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys

# Find out where the keys were actually saved in the container
docker exec quantum-sip-docker-quantum_sip-1 ls -la /app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

# Copy the keys from the container to the host
echo "Copying orderer Falcon public key..."
docker cp quantum-sip-docker-quantum_sip-1:/app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_falcon_public.key crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

echo "Copying orderer Falcon private key..."
docker cp quantum-sip-docker-quantum_sip-1:/app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_falcon_private.key crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

echo "Copying orderer Kyber public key..."
docker cp quantum-sip-docker-quantum_sip-1:/app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_kyber_public.key crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

echo "Copying orderer Kyber private key..."
docker cp quantum-sip-docker-quantum_sip-1:/app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_kyber_private.key crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

# Verify the keys were copied correctly
echo "Verifying the keys were copied..."
ls -la crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/

# Edit your copy_orderer_keys.sh file and add this at the end
# (after the "Verifying the keys were copied..." line)

# Configure orderer to use quantum keys
echo "Creating orderer configuration override..."
mkdir -p config/orderer
cat > config/orderer/orderer.yaml << EOF
General:
  QuantumEnabled: true
  QuantumKeyStore: /var/hyperledger/orderer/quantum_keys
  QuantumKeyTypes:
    - Falcon
    - Kyber
  QuantumSignature: Falcon
  QuantumKeyExchange: Kyber
EOF

echo "✅ Orderer configuration created"

# Output next steps
echo -e "\n===================================="
echo "NEXT STEPS:"
echo "===================================="
echo "1. Make sure your docker-compose.yml mounts the quantum keys directory:"
echo "   volumes:"
echo "     - ./crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys:/var/hyperledger/orderer/quantum_keys"
echo ""
echo "2. Make sure the orderer has the correct environment variables:"
echo "   environment:"
echo "     - ORDERER_GENERAL_QUANTUM_ENABLED=true"
echo "     - ORDERER_GENERAL_QUANTUM_KEYSTORE=/var/hyperledger/orderer/quantum_keys"
echo "     - ORDERER_GENERAL_QUANTUM_KEYTYPES=[\"Falcon\",\"Kyber\"]"
echo ""
echo "3. Mount the orderer configuration override:"
echo "   volumes:"
echo "     - ./config/orderer/orderer.yaml:/var/hyperledger/orderer/config/orderer.yaml"
echo ""
echo "4. Restart the orderer service:"
echo "   docker-compose restart orderer.example.com"
echo "===================================="