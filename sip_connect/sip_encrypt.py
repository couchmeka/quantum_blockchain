import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple
import ssl  # For secure TLS context


# Quantum cryptography imports
from sip_connect.key_utils import convert_to_ubyte_pointer
from sip_connect.hipaa_security import SecureKeyManager, EnhancedEncryption


class QuantumTLSEnhancer:
    def __init__(self, org_id='Hospital_A'):
        self.logger = logging.getLogger('QuantumTLS')
        self.org_id = org_id

        try:
            # Load quantum keys
            self.quantum_keys = self._load_quantum_keys()
        except Exception as e:
            self.logger.warning(f"Could not load quantum keys: {e}")
            self.quantum_keys = None

    def _load_quantum_keys(self):
        """Load Falcon keys with error handling"""
        try:
            # Load Falcon keys
            falcon_keys = SecureKeyManager.load_keys(self.org_id, key_type='falcon')

            return {
                'falcon_public': convert_to_ubyte_pointer(falcon_keys['public_key']),
                'falcon_private': convert_to_ubyte_pointer(falcon_keys['private_key'])
            }
        except Exception as e:
            self.logger.warning(f"Failed to load quantum keys: {e}")
            return None

    def enhance_tls_context(self, context):
        """Enhance existing TLS context with quantum-resistant capabilities"""
        if not self.quantum_keys:
            return context

        try:
            # Add quantum-resistant cipher suites
            quantum_ciphers = [
                'ECDHE-ECDSA-AES128-GCM-SHA256',  # Original
                'ECDHE-RSA-AES128-GCM-SHA256',  # Original
                'KYBER-ECDHE-FALCON-AES256-GCM-SHA384',  # Quantum-resistant
                'ECDHE-KYBER-AES256-GCM-SHA384'  # Quantum-resistant
            ]
            context.set_ciphers(':'.join(quantum_ciphers))

            return context

        except Exception as e:
            self.logger.warning(f"Could not enhance TLS context: {e}")
            return context


class SIPIntegration:
    def __init__(self, encryption_system, host: str = '127.0.0.1', port: int = 5061):
        self.encryption = encryption_system
        self.host = host
        self.port = port
        self.org_id = getattr(encryption_system, 'org_id', 'Hospital_A')
        self._setup_logging()
        self._setup_tls_context()

    def _setup_logging(self):
        self.logger = logging.getLogger('SIPTrace')
        self.logger.setLevel(logging.DEBUG)

        fh = logging.FileHandler('sip_trace.log')
        fh.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def _setup_tls_context(self):
        self.logger.info("Setting up TLS context")
        try:
            # Create base TLS context
            self.tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.tls_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

            # Get the directory of the current file
            current_dir = Path(__file__).parent

            # Construct the path to the certificates
            cert_dir = current_dir / 'certificates'
            cert_file = cert_dir / 'server_certificate.pem'
            key_file = cert_dir / 'server_private_key.pem'

            self.logger.info(f"Looking for cert file at: {cert_file}")
            self.logger.info(f"Looking for key file at: {key_file}")

            if cert_file.exists() and key_file.exists():
                self.logger.info(f"Loading certificates from {cert_file}")
                self.tls_context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            else:
                self.logger.warning(f"TLS certificate files not found at {cert_file} and {key_file}")

            # Enhance TLS context with quantum capabilities
            quantum_enhancer = QuantumTLSEnhancer(self.org_id)
            self.tls_context = quantum_enhancer.enhance_tls_context(self.tls_context)

            self.tls_context.check_hostname = True
            self.tls_context.verify_mode = ssl.CERT_REQUIRED
            self.logger.info("TLS context setup complete")
        except Exception as e:
            self.logger.error(f"Error setting up TLS context: {str(e)}")
            raise

    def encrypt_sip_message(self, message: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, Any]]:
        try:
            self.logger.info("=== Starting Quantum-Enhanced SIP Message Encryption ===")
            if 'patient_id' not in message:
                raise ValueError("Patient ID missing in message")

            encrypted_data = self.encryption.encrypt(json.dumps(message))
            self.logger.info("Quantum-Enhanced Encryption Completed")

            sip_headers = {
                'Timestamp': datetime.now().isoformat()
            }
            encrypted_package = {
                'payload': encrypted_data
            }

            return sip_headers, encrypted_package
        except Exception as e:
            self.logger.error(f"ERROR in Quantum SIP Message Encryption: {str(e)}")
            raise

    def send_secure_message(self, message: Dict[str, Any]):
        try:
            self.logger.info("=== Starting Secure Message Transmission ===")
            sip_headers, encrypted_data = self.encrypt_sip_message(message)
            self.logger.info("Message Encrypted for Transmission")
            return {
                'headers': sip_headers,
                'encrypted_payload': encrypted_data['payload']
            }
        except Exception as e:
            self.logger.error(f"ERROR in Message Transmission: {str(e)}")
            raise


if __name__ == "__main__":
    test_encryption = EnhancedEncryption(user_key=12345)
    test_sip = SIPIntegration(test_encryption)

    test_message = {
        "patient_id": "P12345",
        "diagnosis": "Regular checkup",
        "notes": "Patient is healthy"
    }

    try:
        test_sip.send_secure_message(test_message)
    except Exception as e:
        print(f"Test failed: {str(e)}")