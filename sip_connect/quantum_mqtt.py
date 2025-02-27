import paho.mqtt.client as mqtt
import os
import logging
from typing import Dict, Any
import requests
from pathlib import Path

from sip_connect.key_utils import load_and_convert_keys
from sip_connect.quantum_components import MelodyQuantumGenerator, EnvironmentalEntropy, DEFAULT_MELODY
from sip_connect.hipaa_security import PostQuantumSessionSecurity, HybridSecuritySystem


class QuantumMQTTClient:
    def __init__(self, org_id: str,
                 broker_host: str = os.getenv('MQTT_BROKER_HOST', 'mqtt'),
                 broker_port: int = int(os.getenv('MQTT_BROKER_PORT', 1883))):
        self._setup_logging()
        self.org_id = org_id
        self.broker_host = broker_host
        self.broker_port = broker_port

        # Initialize quantum components
        self.quantum_gen = MelodyQuantumGenerator(DEFAULT_MELODY)
        self.entropy = EnvironmentalEntropy()

        # Load and convert keys using enhanced key_utils
        try:
            converted_keys = load_and_convert_keys(org_id)
            self.post_quantum = PostQuantumSessionSecurity(
                falcon_public_key=converted_keys['falcon_public'],
                falcon_private_key=converted_keys['falcon_private'],
                kyber_public_key=converted_keys['kyber_public'],
                kyber_private_key=converted_keys['kyber_private']
            )
            self.logger.info("Successfully initialized quantum security")
        except Exception as e:
            self.logger.error(f"Failed to initialize quantum security: {e}")
            raise

        self.security = HybridSecuritySystem(
            org_id=org_id,
            user_key=self._generate_user_key(),
            post_quantum=self.post_quantum
        )

        # Initialize MQTT client
        self.client = mqtt.Client()
        self.client.on_message = self._on_message
        self.client.on_connect = self._on_connect

    # In both quantum_mqtt.py and quantum_srtp.py
    def _load_key(self, key_name: str) -> bytes:
        # Use correct path with proper org_id interpolation
        key_path = Path(f'/app/keys/{self.org_id}.example.com') / key_name
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()

            if not key_data:
                self.logger.warning(f"Empty key file: {key_path}")

            self.logger.debug(f"Successfully loaded key: {key_name}")
            return key_data
        except FileNotFoundError:
            self.logger.error(f"Key file not found: {key_path}")
            return b''
        except Exception as e:
            self.logger.error(f"Error loading key {key_name}: {e}")
            return b''

    def handle_payment(self, sender_id: str, receiver_id: str, amount: float, payment_type: str):
        try:
            payload = {
                "function": "ProcessM2MPayment",
                "args": [
                    sender_id,
                    receiver_id,
                    str(amount),
                    payment_type
                ]
            }

            response = requests.post(
                f"{self.gateway_url}/channels/mychannel/chaincodes/quantum",
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                self.logger.info(f"Payment processed: {response.json()}")
                return response.json()
            else:
                raise Exception(f"Payment failed with status {response.status_code}")

        except Exception as e:
            self.logger.error(f"Payment failed: {str(e)}")
            raise

    def _setup_logging(self):
        # Ensure logs directory exists with full permissions
        os.makedirs('/app/logs', exist_ok=True)
        try:
            os.chmod('/app/logs', 0o777)
        except Exception as e:
            print(f"Could not set logs directory permissions: {e}")

        # Clear any existing handlers to prevent duplicate logging
        logging.getLogger('QuantumMQTT').handlers.clear()

        self.logger = logging.getLogger('QuantumMQTT')
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # Prevent log propagation

        # Use a file handler with full path
        file_handler = logging.FileHandler('/app/logs/quantum_mqtt.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Stream handler for console output
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

    def _generate_user_key(self) -> int:
        return int.from_bytes(self.entropy.generate_entropy().to_bytes(32, 'big'), 'big')

    def connect(self):
        self.client.connect(self.broker_host, self.broker_port, 60)
        self.client.loop_start()

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()

    def publish(self, topic: str, message: Dict[str, Any]):
        try:
            encrypted_payload = self.security.encrypt_message(message)
            self.client.publish(topic, encrypted_payload)
            self.logger.info(f"Published encrypted message to topic: {topic}")
        except Exception as e:
            self.logger.error(f"Failed to publish message: {str(e)}")
            raise

    def subscribe(self, topic: str):
        self.client.subscribe(topic)
        self.logger.info(f"Subscribed to topic: {topic}")

    def _on_message(self, _client, _userdata, msg):
        try:
            decrypted_payload = self.security.decrypt_message(msg.payload)

            if isinstance(decrypted_payload, dict) and 'payment' in decrypted_payload:
                payment_info = decrypted_payload['payment']
                self.handle_payment(
                    payment_info['sender'],
                    payment_info['receiver'],
                    float(payment_info['amount']),
                    payment_info['type']
                )

            self.logger.info(f"Processed message from topic: {msg.topic}")
            return decrypted_payload
        except Exception as e:
            self.logger.error(f"Failed to process message: {str(e)}")
            raise

    def _on_connect(self, _client, _userdata, _flags, rc):
        self.logger.info(f"Connected to MQTT broker with result code: {rc}")
        if rc == 0:
            self.logger.info("Successfully connected to MQTT broker")
        else:
            self.logger.error(f"Failed to connect to MQTT broker with code: {rc}")