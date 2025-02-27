#!/bin/bash
# docker_orderer_key_setup.sh
# Uses the quantum_sip container to generate orderer keys

set -e  # Exit on any error

echo "===================================="
echo " Orderer Quantum Key Setup (Docker)"
echo "===================================="

# Step 1: Create directory structure if it doesn't exist
echo "Creating directory structure for orderer quantum keys..."
mkdir -p crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys

# Step 2: Use the quantum_sip container to generate keys (it already has the Python environment set up)
echo "Generating orderer quantum keys using the quantum_sip container..."

# Create a Python script that will be executed inside the container
cat > generate_orderer_keys.py << 'EOF'
import sys
import os
from pathlib import Path

# Set up proper paths
sys.path.append('/app')
sys.path.append('/app/sip_connect')

try:
    from sip_connect.hipaa_security import SecureKeyManager
    from sip_connect.kyber_wrapper import kyber_keygen
    from sip_connect.key_utils import convert_to_ubyte_pointer

    print('Imports successful. Generating keys...')

    # Generate Falcon keys for orderer
    print('Generating Falcon keys...')
    falcon_keys = SecureKeyManager.generate_falcon_keypair('orderer')
    falcon_public_key = falcon_keys['public_key']
    falcon_private_key = falcon_keys['private_key']

    # Generate Kyber keys for orderer
    print('Generating Kyber keys...')
    kyber_public_key, kyber_private_key = kyber_keygen()

    # Convert to paths for the host system
    host_path = Path('/app/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys')
    host_path.mkdir(parents=True, exist_ok=True)

    # Save Falcon keys
    print('Saving Falcon keys...')
    with open(host_path / 'orderer_falcon_public.key', 'wb') as f:
        f.write(falcon_public_key)
    with open(host_path / 'orderer_falcon_private.key', 'wb') as f:
        f.write(falcon_private_key)

    # Save Kyber keys
    print('Saving Kyber keys...')
    with open(host_path / 'orderer_kyber_public.key', 'wb') as f:
        f.write(kyber_public_key)
    with open(host_path / 'orderer_kyber_private.key', 'wb') as f:
        f.write(kyber_private_key)

    print('Successfully saved orderer quantum keys')

except ImportError as e:
    print(f"Import error: {e}")
    print("Module search paths:")
    for path in sys.path:
        print(f"- {path}")
    sys.exit(1)
except Exception as e:
    print(f"Error generating keys: {e}")
    sys.exit(1)
EOF

# Run the script inside the quantum_sip container
docker cp generate_orderer_keys.py quantum-sip-docker-quantum_sip-1:/app/generate_orderer_keys.py
docker exec -it quantum-sip-docker-quantum_sip-1 python /app/generate_orderer_keys.py

# Clean up the temporary script
rm generate_orderer_keys.py

# Step 3: Verify the keys were created correctly
echo "Verifying orderer quantum keys..."
if [ -f "crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_falcon_public.key" ] && \
   [ -f "crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_falcon_private.key" ] && \
   [ -f "crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_kyber_public.key" ] && \
   [ -f "crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/quantum_keys/orderer_kyber_private.key" ]; then
    echo "✅ Orderer quantum keys generated successfully"
else
    echo "❌ Some orderer quantum keys are missing"
    exit 1
fi

# Step 4: Configure orderer to use quantum keys
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

# Step 5: Output instructions for Docker Compose update
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