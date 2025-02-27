#!/bin/bash

# Generate crypto materials if not already present
if [ ! -d "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto" ] || [ -z "$(ls -A /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto)" ]; then
    echo "Generating crypto materials..."
    cryptogen generate --config=/etc/hyperledger/fabric/crypto-config.yaml
fi

# Start bash
exec /bin/bash