import os
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PQC-Verification')

# Expected sizes for Falcon keys
FALCON_KEY_SIZES = {
    'public': 1793,
    'private': 2305
}

def verify_key_size(path: Path, expected_size: int, key_type: str) -> bool:
    """Verify a key file exists and has the correct size"""
    if not path.exists():
        logger.error(f"Missing key file: {path}")
        return False

    actual_size = path.stat().st_size
    if actual_size != expected_size:
        logger.error(f"Incorrect size for {key_type}: Expected {expected_size}, got {actual_size}")
        return False

    logger.info(f"✓ Verified {key_type}: correct size of {actual_size} bytes")
    return True

def verify_quantum_setup(org_id: str) -> dict:
    """Verify quantum cryptographic setup for an organization"""
    results = {
        'quantum_directory': False,
        'falcon_public_key': False,
        'falcon_private_key': False,
        'tls_directory': False
    }

    # Base path for the organization
    base_path = Path(f"crypto-config/peerOrganizations/{org_id}.example.com")

    # Check quantum_keys directory
    quantum_dir = base_path / 'msp/quantum_keys'
    results['quantum_directory'] = quantum_dir.exists()
    if results['quantum_directory']:
        logger.info(f"✓ Verified quantum_keys directory exists for {org_id}")
    else:
        logger.error(f"quantum_keys directory missing for {org_id}")

    # Check Falcon keys
    falcon_paths = {
        'public': quantum_dir / 'falcon_public.key',
        'private': quantum_dir / 'falcon_private.key'
    }

    for key_type, path in falcon_paths.items():
        key_check = verify_key_size(path, FALCON_KEY_SIZES[key_type], f"Falcon {key_type} key")
        results[f'falcon_{key_type}_key'] = key_check

    # Check MSP configuration


    # Check TLS directory
    tls_dir = base_path / 'msp/tlscacerts'
    results['tls_directory'] = tls_dir.exists()
    if results['tls_directory']:
        logger.info(f"✓ Verified TLS certificates directory exists for {org_id}")
    else:
        logger.error(f"TLS certificates directory missing for {org_id}")

    # Print summary
    successful_checks = [k for k, v in results.items() if v]
    failed_checks = [k for k, v in results.items() if not v]

    if all(results.values()):
        logger.info(f"\n✅ All quantum cryptographic checks passed for {org_id}")
    else:
        logger.error(f"\n❌ Some quantum cryptographic checks failed for {org_id}")
        logger.error(f"Successful checks: {', '.join(successful_checks)}")
        logger.error(f"Failed checks: {', '.join(failed_checks)}")

    return results

def main():
    logger.info("Starting Quantum Cryptography Verification")
    logger.info("=============================================")

    orgs = ["Hospital_A", "Hospital_B"]
    all_results = {}

    for org in orgs:
        logger.info(f"\nVerifying {org}")
        logger.info("-" * 20)
        all_results[org] = verify_quantum_setup(org)

    # Final summary
    print("\nFinal Summary")
    print("============")
    for org, results in all_results.items():
        status = "✅ PASS" if all(results.values()) else "❌ FAIL"
        print(f"{org}: {status}")

if __name__ == "__main__":
    main()