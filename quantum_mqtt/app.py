import logging
from quantum_services_init import QuantumServicesInitializer
from pathlib import Path


class MQTTApp:
    def __init__(self, org_id):
        self.org_id = org_id
        self.initializer = QuantumServicesInitializer(org_id)
        self.logger = logging.getLogger(f"MQTTApp_{org_id}")
        self.mqtt = None

    def initialize(self):
        """Initialize MQTT service"""
        try:
            result = self.initializer.initialize_quantum_services()
            if not result['success']:
                raise Exception(f"Initialization failed: {result['error']}")

            self.mqtt = result['mqtt']
            return self.mqtt
        except Exception as e:
            self.logger.error(f"Failed to initialize MQTT service: {e}")
            raise

    def run(self):
        """Main service run method"""
        try:
            self.mqtt.connect()
            self.logger.info("MQTT service started successfully.")

            # Add any long-running logic, message handling, etc.
            # This could be a blocking call, event loop, etc.
        except Exception as e:
            self.logger.error(f"Error in MQTT service: {e}")
        finally:
            self.stop()

    def stop(self):
        """Gracefully stop the service"""
        try:
            self.mqtt.disconnect()
            self.logger.info("MQTT service stopped.")
        except Exception as e:
            self.logger.error(f"Error stopping MQTT service: {e}")