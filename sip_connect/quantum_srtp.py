from sip_connect.key_utils import load_and_convert_keys
from sip_connect.quantum_components import MelodyQuantumGenerator, EnvironmentalEntropy, DEFAULT_MELODY
import hashlib
import logging
from datetime import datetime
from typing import Dict, Any, Tuple
from pathlib import Path

from sip_connect.hipaa_security import PostQuantumSessionSecurity


class QuantumEnhancedSRTP:
    def __init__(self, sip_connection):
        self.org_id = getattr(sip_connection, 'org_id', 'default_org')
        self.logger = logging.getLogger(f"QuantumSRTP_{self.org_id}")

        # Add keys_dir initialization
        self.base_path = Path("/app")
        self.keys_dir = self.base_path / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)  # Ensure keys directory exists

        # Initialize quantum components
        self.quantum_gen = MelodyQuantumGenerator(DEFAULT_MELODY)
        self.entropy = EnvironmentalEntropy()

        # Load and convert keys using enhanced key_utils
        try:
            converted_keys = load_and_convert_keys(self.org_id)

            # Store converted keys for direct SRTP operations
            self.keys = converted_keys

            # Initialize PostQuantumSessionSecurity for session management
            self.post_quantum = PostQuantumSessionSecurity(
                falcon_public_key=converted_keys['falcon_public'],
                falcon_private_key=converted_keys['falcon_private'],
                kyber_public_key=converted_keys['kyber_public'],
                kyber_private_key=converted_keys['kyber_private']
            )

            self.logger.info(f"Successfully loaded keys for {self.org_id}")
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
            raise

        # Store SIP connection
        self.sip = sip_connection

        # Optional: Set up logging file handler
        self._setup_logging()

    def _setup_logging(self):
        """Set up logging with proper directory creation"""
        log_dir = self.base_path / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger('QuantumSRTP')
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler(log_dir / 'quantum_srtp.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

        self.logger.info("Logging initialized for QuantumSRTP")

    def generate_srtp_key(self) -> Tuple[bytes, Dict[str, Any]]:
        """Generate quantum-enhanced SRTP key"""
        try:
            # Generate quantum components
            quantum_key = self.quantum_gen.generate_quantum_key()
            env_entropy = self.entropy.generate_entropy()

            # Combine quantum and classical entropy
            # Use falcon_public instead of public_key to match load_and_convert_keys
            key_material = hashlib.sha256(
                str(quantum_key).encode() +
                str(env_entropy).encode() +
                datetime.now().isoformat().encode() +
                bytes(self.keys['falcon_public'])  # Changed from public_key to falcon_public
            ).digest()

            metadata = {
                'timestamp': datetime.now().isoformat(),
                'quantum_key_id': str(quantum_key),
                'entropy_id': str(env_entropy),
                'falcon_public_path': str(self.keys_dir / f"{self.org_id}_falcon_public.key"),
                'falcon_private_path': str(self.keys_dir / f"{self.org_id}_falcon_private.key")
            }

            self.logger.info("Generated new quantum-enhanced SRTP key")
            return key_material, metadata

        except Exception as e:
            self.logger.error(f"Failed to generate SRTP key: {str(e)}")
            raise

    def setup_srtp_session(self, session_id: str) -> Dict[str, Any]:
        """Set up SRTP session with quantum-enhanced keys"""
        try:
            # Generate key material using the method without additional parameters
            key_material, metadata = self.generate_srtp_key()

            session_config = {
                'session_id': session_id,
                'key_material': key_material,
                'metadata': metadata,
                'created_at': datetime.now().isoformat()
            }

            self.logger.info(f"Set up SRTP session: {session_id}")
            return session_config

        except Exception as e:
            self.logger.error(f"Failed to setup SRTP session: {str(e)}")
            raise

    def rotate_keys(self, session_id: str) -> Dict[str, Any]:
        """Rotate SRTP keys with new quantum entropy"""
        try:
            # Generate new key material and metadata
            new_key_material, new_metadata = self.generate_srtp_key()

            # Create a new session configuration with rotated keys
            rotated_session_config = {
                'session_id': session_id,
                'key_material': new_key_material,
                'metadata': new_metadata,
                'rotated_at': datetime.now().isoformat()
            }

            self.logger.info(f"Rotated keys for session: {session_id}")
            return rotated_session_config

        except Exception as e:
            self.logger.error(f"Failed to rotate keys: {str(e)}")
            raise