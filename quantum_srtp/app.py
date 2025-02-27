import logging
import uuid

from quantum_services_init import QuantumServicesInitializer


class SRTPApp:
    def __init__(self, org_id, debug=False):
        self.initial_session = None
        self.session_id = None
        self.mqtt = None
        self.srtp = None
        self.org_id = org_id
        self.debug = debug
        self.initializer = QuantumServicesInitializer(org_id)

        # Configure logging
        self.logger = logging.getLogger(f"SRTPApp_{org_id}")
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)

    def initialize(self):
        """Initialize SRTP service"""
        try:
            result = self.initializer.initialize_quantum_services()
            if not result['success']:
                raise Exception(f"Initialization failed: {result['error']}")

            self.srtp = result['srtp']
            self.mqtt = result['mqtt']

            # Create session
            self.session_id = f"{self.org_id}_srtp_session_{uuid.uuid4().hex}"
            self.initial_session = self.srtp.setup_srtp_session(self.session_id)

            self.logger.info(f"SRTP session created: {self.session_id}")
            return self.srtp
        except Exception as e:
            self.logger.error(f"Failed to initialize SRTP service: {e}")
            raise

    def run(self):
        """Main service run method"""
        try:
            # Start SRTP service logic
            self.logger.info("SRTP service starting...")

            # Add your specific SRTP service logic here
            # This could be a blocking call, event loop, etc.
            while True:
                # Example: periodic tasks, connection handling, etc.
                pass

        except Exception as e:
            self.logger.error(f"Error in SRTP service: {e}")
        finally:
            self.stop()

    def stop(self):
        """Gracefully stop the service"""
        try:
            self.logger.info("Stopping SRTP service...")
            # Add any cleanup or shutdown logic
            if hasattr(self.srtp, 'stop'):
                self.srtp.stop()
        except Exception as e:
            self.logger.error(f"Error stopping SRTP service: {e}")