import logging
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from sip_connect.falcon_wrapper import falcon_generate_keypair
from sip_connect.kyber_wrapper import kyber_keygen  # Import Kyber keygen function

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecuritySetupValidator:
    def __init__(self):
        self.cert_dir = Path('certificates')
        self.keys_dir = Path('keys')
        self.base_dir = Path('.')

    def create_directories(self):
        """Create necessary directories if they don't exist"""
        dirs = [self.cert_dir, self.keys_dir]
        for dir_path in dirs:
            dir_path.mkdir(exist_ok=True)
            logger.info(f"Created directory: {dir_path}")

    def generate_tls_certificates(self):
        """Generate TLS certificates for secure communication"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Hospital Network"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now()
        ).not_valid_after(
            datetime.now() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        with open(self.cert_dir / 'server_private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.cert_dir / 'server_certificate.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("Generated TLS certificates")

    def setup_falcon_keys(self, org_ids=None):
        """Generate Falcon keys for each organization"""
        if org_ids is None:
            org_ids = ['Hospital_A', 'Hospital_B']

        for org_id in org_ids:
            try:
                public_key, private_key = falcon_generate_keypair()

                with open(self.keys_dir / f'{org_id}_falcon_public.key', 'wb') as f:
                    f.write(public_key)

                with open(self.keys_dir / f'{org_id}_falcon_private.key', 'wb') as f:
                    f.write(private_key)

                logger.info(f"Generated Falcon keys for {org_id}")
            except Exception as e:
                logger.error(f"Failed to generate Falcon keys for {org_id}: {e}")
                raise

    def setup_kyber_keys(self, org_ids=None):
        """Generate Kyber keys for each organization"""
        if org_ids is None:
            org_ids = ['Hospital_A', 'Hospital_B']

        for org_id in org_ids:
            try:
                kyber_public_key, kyber_private_key = kyber_keygen()

                with open(self.keys_dir / f'{org_id}_kyber_public.key', 'wb') as f:
                    f.write(kyber_public_key)

                with open(self.keys_dir / f'{org_id}_kyber_private.key', 'wb') as f:
                    f.write(kyber_private_key)

                logger.info(f"Generated Kyber keys for {org_id}")
            except Exception as e:
                logger.error(f"Failed to generate Kyber keys for {org_id}: {e}")
                raise

    def validate_setup(self):
        """Validate the entire setup"""
        issues = []

        # Check directories
        for dir_path in [self.cert_dir, self.keys_dir]:
            if not dir_path.exists():
                issues.append(f"Missing directory: {dir_path}")

        # Check TLS certificates
        cert_files = ['server_certificate.pem', 'server_private_key.pem']
        for cert_file in cert_files:
            if not (self.cert_dir / cert_file).exists():
                issues.append(f"Missing TLS certificate file: {cert_file}")

        # Check Falcon keys
        for org_id in ['Hospital_A', 'Hospital_B']:
            for key_type in ['public', 'private']:
                key_file = f'{org_id}_falcon_{key_type}.key'
                if not (self.keys_dir / key_file).exists():
                    issues.append(f"Missing Falcon key file: {key_file}")

        # Check Kyber keys
        for org_id in ['Hospital_A', 'Hospital_B']:
            for key_type in ['public', 'private']:
                key_file = f'{org_id}_kyber_{key_type}.key'
                if not (self.keys_dir / key_file).exists():
                    issues.append(f"Missing Kyber key file: {key_file}")

        return issues

    def fix_setup(self):
        """Fix any setup issues"""
        logger.info("Starting setup validation and fix...")

        self.create_directories()

        if not all((self.cert_dir / f).exists() for f in ['server_certificate.pem', 'server_private_key.pem']):
            logger.info("Generating TLS certificates...")
            self.generate_tls_certificates()

        self.setup_falcon_keys()
        self.setup_kyber_keys()

        issues = self.validate_setup()
        if issues:
            logger.warning("Remaining issues after fix:")
            for issue in issues:
                logger.warning(f"  - {issue}")
            return False

        logger.info("Setup completed successfully")
        return True


def main():
    validator = SecuritySetupValidator()
    validator.fix_setup()


if __name__ == "__main__":
    main()