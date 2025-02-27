import http.server
import os
import socketserver
from threading import Thread
import sys
from pathlib import Path
import uuid
import logging
from sip_connect.kyber_wrapper import kyber_keygen

# Get absolute path to root directory
base_dir = Path(__file__).parent
root_path = str(base_dir)
sip_connect_path = str(base_dir / 'sip_connect')

# Add BOTH paths to Python path
sys.path.append(root_path)
sys.path.append(sip_connect_path)

# Import after path setup
from sip_connect.key_utils import convert_to_ubyte_pointer
from sip_connect.setup_hipaa import setup_multi_hospital_environment
from sip_connect.hipaa_security import SecureKeyManager, EnhancedEncryption
from sip_connect.quantum_srtp import QuantumEnhancedSRTP
from sip_connect.quantum_mqtt import QuantumMQTTClient
from sip_connect.sip_encrypt import SIPIntegration


logger = logging.getLogger('QuantumServices')


def setup_logging():
    try:
        # Determine the base log directory
        log_dir = '/app/logs'
        log_file = os.path.join(log_dir, 'quantum_services_detailed.log')

        # Create log directory with full permissions
        os.makedirs(log_dir, exist_ok=True)
        os.chmod(log_dir, 0o777)

        # Ensure log file is writable
        if not os.path.exists(log_file):
            open(log_file, 'a').close()
        os.chmod(log_file, 0o666)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, mode='a'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        # Log successful logging setup
        logger = logging.getLogger('QuantumServices')
        logger.info(f"Logging initialized. Log file: {log_file}")

    except Exception as e:
        # Fallback logging if setup fails
        print(f"CRITICAL: Failed to set up logging: {e}")
        logging.basicConfig(level=logging.INFO)


class QuantumServicesInitializer:
    def __init__(self, org_id: str):
        self.org_id = org_id
        self.logger = logging.getLogger(__name__)

        # Define directories
        self.quantum_services_dir = Path(f'quantum_services/organizations/{org_id}.example.com')
        self.quantum_mqtt_dir = self.quantum_services_dir / 'mqtt'
        self.quantum_srtp_dir = self.quantum_services_dir / 'srtp'
        self.quantum_keys_dir = self.quantum_services_dir / 'keys'

    def initialize_quantum_services(self):
        """Initialize quantum services with both quantum and classical certificates"""
        try:
            # Create directory structure
            self._create_directories()

            # Print out directory paths for verification
            print(f"Quantum services directory: {self.quantum_services_dir}")
            print(f"Quantum keys directory: {self.quantum_keys_dir}")

            # First, ensure TLS certificates are set up
            setup_multi_hospital_environment()
            self.logger.info("TLS certificates generated successfully")

            # Generate quantum keys using SecureKeyManager
            falcon_keys = SecureKeyManager.generate_falcon_keypair(self.org_id)
            self.logger.debug(f"Generated Falcon keys for {self.org_id}")

            # Convert Falcon keys to proper format
            falcon_public_ptr = convert_to_ubyte_pointer(falcon_keys['public_key'])
            falcon_private_ptr = convert_to_ubyte_pointer(falcon_keys['private_key'])

            # Call kyber_keygen() without arguments since it handles its own arrays internally
            kyber_keys = SecureKeyManager.generate_kyber_keypair(self.org_id)
            kyber_public_ptr = convert_to_ubyte_pointer(kyber_keys['public_key'])
            kyber_private_ptr = convert_to_ubyte_pointer(kyber_keys['private_key'])
            self.logger.debug(f"Generated Falcon keys for {self.org_id}")

            # Combine all keys
            quantum_keys = {
                'falcon': {
                    'public_key': falcon_public_ptr,
                    'private_key': falcon_private_ptr
                },
                'kyber': {
                    'public_key': kyber_public_ptr,
                    'private_key': kyber_private_ptr
                }
            }

            # Save the keys
            self._save_keys(quantum_keys)

            # Initialize services
            srtp, mqtt = self._initialize_services(quantum_keys)

            self.logger.info(f"Successfully initialized quantum services for {self.org_id}")
            return {
                'success': True,
                'quantum_keys': quantum_keys,
                'srtp': srtp,
                'mqtt': mqtt
            }

        except Exception as e:
            self.logger.error(f"Failed to initialize quantum services: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def _create_directories(self):
        """Create quantum services directory structure"""
        dirs = [
            self.quantum_services_dir,
            self.quantum_mqtt_dir,
            self.quantum_srtp_dir,
            self.quantum_keys_dir
        ]
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

    def generate_keys_for_org(self, org_id: str, logger):
        """Generate both Falcon and Kyber keys for an organization"""
        try:
            logger.info(f"Generating quantum keys for {self.org_id}")

            # Generate Falcon keys
            falcon_keys = SecureKeyManager.generate_falcon_keypair(self.org_id)

            # Fix the key structure
            falcon_public_ptr = convert_to_ubyte_pointer(falcon_keys['public_key'])
            falcon_private_ptr = convert_to_ubyte_pointer(falcon_keys['private_key'])

            # Generate Kyber keys with proper type conversion
            kyber_public_key, kyber_private_key = kyber_keygen()

            return {
                'falcon': {
                    'public_key': falcon_public_ptr,
                    'private_key': falcon_private_ptr
                },
                'kyber': {
                    'public_key': kyber_public_key,
                    'private_key': kyber_private_key
                }
            }

        except Exception as e:
            logger.error(f"Error generating quantum keys: {str(e)}")
            raise

    def _save_keys(self, keys: dict):
        """Save quantum keys with proper type handling"""
        try:
            # Convert Falcon pointers to bytes
            falcon_public_bytes = bytes(keys['falcon']['public_key'][:1793])
            falcon_private_bytes = bytes(keys['falcon']['private_key'][:2305])

            # Kyber keys are already in bytes format
            kyber_public_bytes = keys['kyber']['public_key']
            kyber_private_bytes = keys['kyber']['private_key']

            # Save keys
            save_path = self.quantum_keys_dir
            save_path.mkdir(parents=True, exist_ok=True)

            with open(save_path / 'falcon_public.key', 'wb') as f:
                f.write(falcon_public_bytes)

            with open(save_path / 'falcon_private.key', 'wb') as f:
                f.write(falcon_private_bytes)

            with open(save_path / 'kyber_public.key', 'wb') as f:
                f.write(kyber_public_bytes)

            with open(save_path / 'kyber_private.key', 'wb') as f:
                f.write(kyber_private_bytes)

        except Exception as e:
            logger.error(f"Failed to save keys: {str(e)}")
            raise

    def _initialize_services(self, keys):
        """Initialize SRTP and MQTT services"""
        try:
            # Generate a user key
            user_key = self._generate_user_key()

            # Create encryption system
            encryption_system = EnhancedEncryption(
                user_key=user_key,
                org_id=self.org_id,
                shared_keys=keys
            )

            # Create SIP integration object
            sip_connection = SIPIntegration(
                encryption_system,
                host='127.0.0.1',
                port=5061
            )

            # Initialize SRTP
            srtp = QuantumEnhancedSRTP(sip_connection)

            # Initialize MQTT
            mqtt = QuantumMQTTClient(self.org_id)

            return srtp, mqtt

        except Exception as e:
            self.logger.error(f"Failed to initialize services: {str(e)}")
            raise

    def _generate_user_key(self):
        """Generate a deterministic user key"""
        import hashlib
        key_seed = f"quantum_key_{self.org_id}"
        key_hash = hashlib.sha256(key_seed.encode()).hexdigest()
        return int(key_hash, 16) % (2 ** 32)


def run_health_server():
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler

    try:
        with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
            logging.info(f"Health check server running on 0.0.0.0:{PORT}")
            httpd.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start health check server: {e}")

def main():
    setup_logging()
    orgs = ["Hospital_A", "Hospital_B"]

    for org in orgs:
        # Create initializer
        initializer = QuantumServicesInitializer(org)

        # Initialize quantum services
        result = initializer.initialize_quantum_services()

        if result['success']:
            logger.info(f"Successfully initialized quantum services for {org}")

            # Get initialized services
            srtp = result['srtp']
            mqtt = result['mqtt']

            # Generate a session ID
            session_id = f"{org}_session_{uuid.uuid4().hex}"

            # Set up SRTP session
            initial_session = srtp.setup_srtp_session(session_id)
            logger.info(f"SRTP session created: {session_id}")

            # Connect MQTT
            mqtt.connect()
            logger.info(f"MQTT connected for {org}")
        else:
            logger.error(f"Failed to initialize quantum services for {org}: {result['error']}")

        # Start the health check server in a separate thread
    health_thread = Thread(target=run_health_server, daemon=True)
    health_thread.start()

    # Add a small delay to ensure thread starts
    import time
    time.sleep(2)

    # Check if thread is alive
    print(f"Health server thread alive: {health_thread.is_alive()}")

    # Keep the main thread running
    health_thread.join()

if __name__ == "__main__":
    main()

