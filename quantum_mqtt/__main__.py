# __main__.py
from quantum_services_init import QuantumServicesInitializer

def main():
    initializer = QuantumServicesInitializer("Hospital_A")
    result = initializer.initialize_quantum_services()
    if result['success']:
        mqtt = result['mqtt']
        mqtt.connect()

if __name__ == "__main__":
    main()

# app.py
# Keep minimal imports needed by other components
from quantum_services_init import QuantumMQTTClient