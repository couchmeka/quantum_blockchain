import sys
from pathlib import Path
import logging
import ctypes
import yaml

# Get absolute path to sip_connect
base_dir = Path(__file__).parent
sip_connect_path = str(base_dir / 'sip_connect')

# Add to Python path
sys.path.append(sip_connect_path)

from sip_connect.hipaa_security import HyperledgerHealthInterface, SecureKeyManager
from quantum_cryptogen import convert_to_ubyte_pointer


class QuantumMSPManager:
    def __init__(self, org_id: str, base_path="/app"):
        self.org_id = org_id
        self.base_path = Path(base_path)
        self.msp_dir = self.base_path / "crypto-config" / "peerOrganizations" / f"{org_id}.example.com" / "msp"
        self.logger = self._setup_logging()
        self.health_interface = HyperledgerHealthInterface(org_id)

    def _setup_logging(self):
        """Configure detailed logging"""
        logging_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.DEBUG,
            format=logging_format,
            handlers=[
                logging.FileHandler(self.base_path / 'quantum_msp_init.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('QuantumMSPManager')

    def initialize_org(self):
        """Initialize organization's MSP structure with quantum security"""
        try:
            # Create all necessary directories
            self._create_directory_structure()

            # Generate quantum-enhanced keys
            keys = self._generate_and_save_keys()

            # Create MSP configurations
            self._create_msp_configs()

            # Initialize peer-specific configurations
            self._initialize_peer_configs()

            self.logger.info(f"Successfully initialized {self.org_id} organization")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.org_id}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _create_directory_structure(self):
        """Create complete directory structure for organization"""
        dirs = [
            self.msp_dir / d for d in [
                'admincerts',
                'cacerts',
                'keystore',
                'signcerts',
                'tlscacerts',
                'quantum_keys'
            ]
        ]

        # Add peer directories
        peer_dir = self.base_path / "crypto-config" / "peerOrganizations" / f"{self.org_id}.example.com" / "peers"
        dirs.extend([
            peer_dir / f"peer0.{self.org_id}.example.com" / "msp" / d
            for d in ['admincerts', 'cacerts', 'keystore', 'signcerts', 'tlscacerts', 'quantum_keys']
        ])

        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Created directory: {dir_path}")

    def _generate_and_save_keys(self):
        """Generate and save quantum keys"""
        try:
            # Generate Falcon keys
            keys = SecureKeyManager.generate_falcon_keypair(self.org_id)

            # Convert keys to proper format
            converted_keys = {
                'public_key': convert_to_ubyte_pointer(keys['public_key']),
                'private_key': convert_to_ubyte_pointer(keys['private_key'])
            }

            # Save keys in quantum_keys directory
            quantum_keys_dir = self.msp_dir / 'quantum_keys'

            # Convert pointer to bytes
            public_key_array = ctypes.cast(
                converted_keys['public_key'],
                ctypes.POINTER(ctypes.c_ubyte * 1793)
            ).contents
            private_key_array = ctypes.cast(
                converted_keys['private_key'],
                ctypes.POINTER(ctypes.c_ubyte * 2305)
            ).contents

            # Save the keys
            with open(quantum_keys_dir / 'falcon_public.key', 'wb') as f:
                f.write(bytes(public_key_array[0:1793]))
            with open(quantum_keys_dir / 'falcon_private.key', 'wb') as f:
                f.write(bytes(private_key_array[0:2305]))

            return converted_keys

        except Exception as e:
            self.logger.error(f"Error generating keys: {e}")
            raise

    def _create_msp_configs(self):
        """Create MSP configuration files"""
        config = {
            'NodeOUs': {
                'Enable': True,
                'ClientOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "client"
                },
                'PeerOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "peer"
                },
                'AdminOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "admin"
                },
                'OrdererOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "orderer"
                }
            },
            'QuantumExtensions': {
                'Enable': True,
                'KeyTypes': ['Falcon', 'Kyber'],
                'KeyStore': 'quantum_keys',
                'SecurityLevel': 'quantum-resistant'
            }
        }

        # Save main MSP config
        config_path = self.msp_dir / "config.yaml"
        with open(config_path, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False)

    def _initialize_peer_configs(self):
        """Initialize peer-specific configurations"""
        peer_base = self.base_path / "crypto-config" / "peerOrganizations" / f"{self.org_id}.example.com" / "peers"
        peer_path = peer_base / f"peer0.{self.org_id}.example.com" / "msp"

        # Copy quantum keys to peer MSP
        self._copy_quantum_keys(peer_path)

        # Create peer config
        config = {
            'NodeOUs': {
                'Enable': True,
                'ClientOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "client"
                },
                'PeerOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "peer"
                },
                'AdminOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "admin"
                },
                'OrdererOUIdentifier': {
                    'Certificate': f"cacerts/ca.{self.org_id}.example.com-cert.pem",
                    'OrganizationalUnitIdentifier': "orderer"
                }
            },
            'QuantumExtensions': {
                'Enable': True,
                'KeyTypes': ['Falcon', 'Kyber'],
                'KeyStore': 'quantum_keys',
                'SecurityLevel': 'quantum-resistant'
            }
        }

        # Save config directly to peer path
        config_path = peer_path / "config.yaml"
        with open(config_path, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False)

    def _copy_quantum_keys(self, peer_path: Path):
        """Copy quantum keys to peer directory"""
        import shutil
        src_keys_dir = self.msp_dir / 'quantum_keys'
        dst_keys_dir = peer_path / 'quantum_keys'

        if src_keys_dir.exists():
            if dst_keys_dir.exists():
                shutil.rmtree(dst_keys_dir)
            shutil.copytree(src_keys_dir, dst_keys_dir)


def main():
    orgs = ["Hospital_A", "Hospital_B"]

    for org in orgs:
        print(f"\nInitializing {org} organization...")
        manager = QuantumMSPManager(org)
        success = manager.initialize_org()
        print(f"Organization {org} initialization: {'Successful' if success else 'Failed'}")


if __name__ == "__main__":
    main()