import logging
from datetime import datetime
import hashlib
import time
from typing import Dict, Any
from collections import defaultdict
import json
from sip_connect.quantum_srtp import QuantumEnhancedSRTP
from sip_connect.quantum_msp import QuantumMSPWrapper
from sip_connect.sip_encrypt import SIPIntegration


class SIPDialogManager:
    """Manages SIP dialog states and transactions"""

    def __init__(self):
        self.dialog_state = {}
        self.transaction_history = []
        self.active_dialogs = defaultdict(dict)

    def create_dialog(self, call_id: str, tags: dict) -> str:
        """Creates and tracks a new SIP dialog"""
        dialog_id = f"{call_id};from-tag={tags.get('from')};to-tag={tags.get('to')}"
        self.dialog_state[dialog_id] = {
            'state': 'established',
            'created': datetime.now(),
            'last_activity': datetime.now(),
            'refresh_count': 0
        }
        return dialog_id

    def update_dialog(self, dialog_id: str, state: str = None) -> None:
        """Updates dialog state and last activity timestamp"""
        if dialog_id in self.dialog_state:
            if state:
                self.dialog_state[dialog_id]['state'] = state
            self.dialog_state[dialog_id]['last_activity'] = datetime.now()
            self.dialog_state[dialog_id]['refresh_count'] += 1

    def cleanup_expired_dialogs(self, max_age: int = 3600) -> None:
        """Removes dialogs that have been inactive for the specified duration"""
        current_time = datetime.now()
        expired = [
            dialog_id for dialog_id, info in self.dialog_state.items()
            if (current_time - info['last_activity']).total_seconds() > max_age
        ]
        for dialog_id in expired:
            del self.dialog_state[dialog_id]


class SIPRateLimiter:
    """Implements rate limiting for SIP messages"""

    def __init__(self):
        self.rate_limits = {
            'messages_per_second': 10,
            'max_concurrent_dialogs': 100,
            'max_requests_per_dialog': 1000
        }
        self.message_counter = defaultdict(list)
        self.dialog_counters = defaultdict(int)

    def check_rate_limit(self, sender: str, dialog_id: str = None) -> bool:
        """
        Checks if the sender has exceeded rate limits
        Returns False if rate limit exceeded, True otherwise
        """
        current_time = time.time()

        # Clean old entries
        self.message_counter[sender] = [
            t for t in self.message_counter[sender]
            if t > current_time - 1
        ]

        # Check message rate
        if len(self.message_counter[sender]) >= self.rate_limits['messages_per_second']:
            return False

        # Check dialog limits if dialog_id provided
        if dialog_id:
            if self.dialog_counters[dialog_id] >= self.rate_limits['max_requests_per_dialog']:
                return False
            self.dialog_counters[dialog_id] += 1

        self.message_counter[sender].append(current_time)
        return True

    def reset_counters(self, dialog_id: str = None) -> None:
        """Resets counters for a specific dialog or all if none specified"""
        if dialog_id:
            self.dialog_counters[dialog_id] = 0
        else:
            self.dialog_counters.clear()
            self.message_counter.clear()


class EnhancedSIPIntegration(SIPIntegration):
    def __init__(self, encryption_system, host: str = '127.0.0.1', port: int = 5061, org_id: str = 'Hospital_A'):
        super().__init__(encryption_system, host, port)
        self.org_id = org_id
        self.quantum_msp = QuantumMSPWrapper(self.org_id)
        self.srtp = QuantumEnhancedSRTP(self)

        # Clear any existing handlers from parent class
        logger = logging.getLogger('SIPTrace')
        if logger.handlers:
            logger.handlers = []

        # Setup our own logging
        self._setup_logging()

        # Initialize new components
        self.dialog_manager = SIPDialogManager()
        self.rate_limiter = SIPRateLimiter()

        # Session refresh settings
        self.session_refresh_interval = 1800  # 30 minutes
        self.min_session_expires = 90  # minimum session expiry
        self.last_refresh = datetime.now()

        # Options ping settings
        self.options_ping_interval = 30  # seconds
        self.last_options_ping = datetime.now()

    def refresh_srtp_session(self, dialog_id: str) -> Dict[str, str]:
        try:
            if self.srtp.rotate_keys(dialog_id):
                self.dialog_manager.update_dialog(dialog_id)
                self.last_refresh = datetime.now()

            return {
                'Session-Expires': f'{self.session_refresh_interval}',
                'Min-SE': f'{self.min_session_expires}',
                'Supported': 'timer',
                'Require': 'timer'
            }
        except Exception as e:
            self.logger.error(f"Session refresh failed: {str(e)}")
            raise

    def authenticate_session(self, session_id):
        """
        Authenticate a session using session_id, with logging for auditing.
        """
        print(f"Authenticating session ID: {session_id}")  # Log the session_id
        return True  # Simulate successful authentication

    def _setup_logging(self):
        """Set up detailed logging for SIP operations"""
        logger = logging.getLogger('SIPTrace')
        logger.setLevel(logging.DEBUG)

        # Create file handler
        fh = logging.FileHandler('sip_trace.log')
        fh.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)

        # Add handler
        logger.addHandler(fh)
        self.logger = logger

    def send_secure_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced secure message sending with rate limiting, dialog management, and quantum MSP"""
        try:
            sender_id = self.host

            # Check rate limits using host as sender
            if not self.rate_limiter.check_rate_limit(sender_id):
                return self.handle_sip_response(429, "Too Many Requests")

            # Create or update dialog using host as sender
            call_id = hashlib.sha256(f"{sender_id}{time.time()}".encode()).hexdigest()
            tags = {
                'from': hashlib.sha256(sender_id.encode()).hexdigest()[:8],
                'to': hashlib.sha256(self.host.encode()).hexdigest()[:8]
            }

            # Initialize dialog_id before message encryption
            dialog_id = self.dialog_manager.create_dialog(call_id, tags)
            if not dialog_id:
                return self.handle_sip_response(500, "Failed to create dialog")

            # Original message encryption and transmission
            try:
                sip_headers, encrypted_data = self.encrypt_sip_message(message)
            except Exception as e:
                self.logger.error(f"Message encryption failed: {str(e)}")
                return self.handle_sip_response(500, "Encryption failed")

            # Add dialog information
            sip_headers.update({
                'Call-ID': call_id,
                'From': f'<sip:{sender_id}@{self.host}>;tag={tags["from"]}',
                'To': f'<sip:{self.host}>;tag={tags["to"]}',
                'Dialog-ID': dialog_id
            })

            # Check for session refresh
            if (datetime.now() - self.last_refresh).total_seconds() > self.session_refresh_interval:
                self.refresh_session(dialog_id)

            # Check for options ping
            if (datetime.now() - self.last_options_ping).total_seconds() > self.options_ping_interval:
                self.send_options_ping()

            # Add quantum MSP enhancement
            try:
                enhanced_identity = self.quantum_msp.enhance_identity({
                    'org_id': self.org_id,
                    'dialog_id': dialog_id,
                    'call_id': call_id,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                self.logger.error(f"Quantum MSP enhancement failed: {str(e)}")
                # Continue without MSP enhancement rather than failing the message
                enhanced_identity = None

            # Combine all data
            transmission_data = {
                'headers': sip_headers,
                'encrypted_payload': encrypted_data['payload'],
                'metadata': encrypted_data['metadata'],
                'quantum_msp': enhanced_identity if enhanced_identity else None
            }

            self.logger.info(f"Secure message sent successfully for dialog {dialog_id}")
            return transmission_data

        except Exception as e:
            self.logger.error(f"Failed to send secure message: {str(e)}")
            return self.handle_sip_response(500, str(e))

    def decrypt_secure_message(self, transmission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt SIP message with all security layers"""
        try:
            # First verify the dialog
            dialog_id = transmission_data['headers'].get('Dialog-ID')
            if not dialog_id or not self.dialog_manager.dialog_state.get(dialog_id):
                raise ValueError(f"Invalid dialog ID: {dialog_id}")

            # Extract the encrypted components
            encrypted_payload = transmission_data['encrypted_payload']
            metadata = transmission_data.get('metadata', {})

            # Decrypt using your existing HybridSecuritySystem
            try:
                # Convert to proper format for HybridSecuritySystem
                encrypted_package = json.dumps({
                    'encrypted_data': encrypted_payload,
                    'metadata': metadata
                }).encode('utf-8')

                decrypted_data = self.encryption.decrypt(encrypted_package)

                # Add verification info
                decrypted_data.update({
                    'dialog_id': dialog_id,
                    'decrypted_at': datetime.now().isoformat()
                })

                self.logger.info(f"Message decrypted successfully for dialog {dialog_id}")
                return decrypted_data

            except Exception as e:
                self.logger.error(f"Decryption failed: {str(e)}")
                return self.handle_sip_response(500, "Decryption failed")

        except Exception as e:
            self.logger.error(f"Failed to decrypt secure message: {str(e)}")
            return self.handle_sip_response(500, str(e))

    def refresh_session(self, dialog_id: str) -> Dict[str, str]:
        """Implements SIP Session Refresh"""
        try:
            self.logger.info(f"Initiating SIP session refresh for dialog {dialog_id}")

            if not self.dialog_manager.dialog_state.get(dialog_id):
                raise ValueError(f"Dialog {dialog_id} not found")

            self.dialog_manager.update_dialog(dialog_id)
            self.last_refresh = datetime.now()

            return {
                'Session-Expires': f'{self.session_refresh_interval}',
                'Min-SE': f'{self.min_session_expires}',
                'Supported': 'timer',
                'Require': 'timer'
            }

        except Exception as e:
            self.logger.error(f"Session refresh failed: {str(e)}")
            raise

    def send_options_ping(self) -> Dict[str, str]:
        """Implements SIP Options Ping"""
        try:
            self.last_options_ping = datetime.now()
            return {
                'Via': f'SIP/2.0/TLS {self.host}',
                'Max-Forwards': '70',
                'To': f'<sip:{self.host}>',
                'From': f'<sip:{self.host}>',
                'Call-ID': f'{hashlib.sha256(str(time.time()).encode()).hexdigest()}',
                'CSeq': '1 OPTIONS',
                'Accept': 'application/sdp',
                'Content-Length': '0'
            }
        except Exception as e:
            self.logger.error(f"Options ping failed: {str(e)}")
            raise

    def handle_sip_response(self, response_code: int, reason: str = None) -> Dict[str, Any]:
        """Enhanced SIP response handling"""
        error_responses = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            408: 'Request Timeout',
            429: 'Too Many Requests',
            480: 'Temporarily Unavailable',
            486: 'Busy Here',
            500: 'Server Internal Error',
            503: 'Service Unavailable'
        }

        response = {
            'code': response_code,
            'reason': error_responses.get(response_code, reason or 'Unknown Error'),
            'timestamp': datetime.now().isoformat()
        }

        self.logger.warning(f"SIP Response: {response}")
        return response

    def cleanup(self) -> None:
        """Cleanup method for maintaining dialog and rate limit states"""
        try:
            # Cleanup expired dialogs
            self.dialog_manager.cleanup_expired_dialogs()

            # Reset rate limiters for expired dialogs
            for dialog_id in self.rate_limiter.dialog_counters.copy():
                if dialog_id not in self.dialog_manager.dialog_state:
                    self.rate_limiter.reset_counters(dialog_id)

        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")