import logging

from fastapi import FastAPI
from fastapi.security import HTTPBearer

from sip_connect.hipaa_security import HyperledgerHealthInterface
from sip_connect.sip_encrypt import SIPIntegration


class SIPApp:
    def __init__(self, org_id):
        self.org_id = org_id
        self.logger = logging.getLogger(f"SIPApp_{org_id}")
        self.health_interface = None
        self.sip_integration = None
        self.app = FastAPI()
        self.security = HTTPBearer()

    def initialize(self):
        """Initialize SIP service components"""
        try:
            # Create Hyperledger Health Interface
            self.health_interface = HyperledgerHealthInterface(self.org_id)

            # Create SIP integration - CORRECT WAY
            self.sip_integration = SIPIntegration(
                encryption_system=self.health_interface.security,  # or .encryption depending on your setup
                host='127.0.0.1',
                port=5061
            )

            self.logger.info(f"SIP service initialized for {self.org_id}")
            return self

        except Exception as e:
            self.logger.error(f"Failed to initialize SIP service: {e}")
            raise

    def run(self):
        """Run the SIP service"""
        try:
            # Specific SIP service logic
            self.logger.info("SIP service running...")

            # Example: Add your service-specific running logic
            while True:
                # Placeholder for actual SIP service implementation
                # Could include:
                # - Listening for connections
                # - Processing SIP messages
                # - Maintaining session state
                pass

        except Exception as e:
            self.logger.error(f"Error in SIP service: {e}")
        finally:
            self.stop()

    def stop(self):
        """Gracefully stop the SIP service"""
        try:
            self.logger.info("Stopping SIP service...")
            # Add any necessary cleanup logic
        except Exception as e:
            self.logger.error(f"Error stopping SIP service: {e}")