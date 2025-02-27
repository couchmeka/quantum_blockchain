from pathlib import Path

from _datetime import timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta


def setup_directories(org_id: str):
    """
    Create directories and generate a private key for a specific organization

    Args:
        org_id (str): Unique identifier for the organization

    Returns:
        bool: True if setup is successful
    """
    # Create main directories
    Path('keys').mkdir(exist_ok=True)
    Path('certificates').mkdir(exist_ok=True)
    Path('logs').mkdir(exist_ok=True)

    # Generate and save private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    key_path = f'keys/{org_id}_private_key.pem'
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"Created directories and generated key for {org_id}")
    return True


def generate_self_signed_cert(
        common_name='localhost',
        org_name='Your Organization',
        days_valid=365
):
    """
    Generate a self-signed SSL/TLS certificate for an organization

    Args:
        common_name (str): Common name for the certificate (typically domain name)
        org_name (str): Organization name
        days_valid (int): Number of days the certificate is valid

    Returns:
        Tuple[str, str]: Paths to private key and certificate
    """
    # Ensure certificates directory exists
    cert_dir = Path('certificates')
    cert_dir.mkdir(exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Filename based on organization name
    org_safe_name = ''.join(c if c.isalnum() or c in ['_', '-'] else '_' for c in org_name)
    private_key_path = cert_dir / f'{org_safe_name}_private_key.pem'
    cert_path = cert_dir / f'{org_safe_name}_certificate.pem'

    # Write private key
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved to {private_key_path}")

    # Get the public key
    public_key = private_key.public_key()

    # Ensure org_name is a string (convert from bytes if necessary)
    if isinstance(org_name, bytes):
        org_name = org_name.decode('utf-8')

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Set certificate validity
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=days_valid)

    # Create the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name)
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())

    # Write the certificate
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate saved to {cert_path}")

    return str(private_key_path), str(cert_path)


def generate_org_certificates(org_id: str):
    """Generate TLS certificates for an organization"""
    try:
        cert_dir = Path('certificates')
        cert_dir.mkdir(exist_ok=True)

        # Generate CA key and certificate
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        ])

        ca_cert = x509.CertificateBuilder().subject_name(
            ca_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).sign(ca_key, hashes.SHA256())

        # Save CA certificate and key
        with open(cert_dir / f"{org_id}_ca.key", "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(cert_dir / f"{org_id}_ca.pem", "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        return True

    except Exception as e:
        print(f"Failed to generate certificates for {org_id}: {e}")
        return False


def setup_multi_hospital_environment():
    """Setup keys and certificates for multiple hospitals"""
    try:
        # Step 1: Setup directories and keys
        setup_directories('Hospital_A')
        setup_directories('Hospital_B')

        # Step 2: Generate self-signed certs for SIP/MQTT services
        generate_self_signed_cert(
            common_name='hospital_a.localhost',
            org_name='Hospital A Secure Communications',
            days_valid=365
        )

        generate_self_signed_cert(
            common_name='hospital_b.localhost',
            org_name='Hospital B Secure Communications',
            days_valid=365
        )

        # Step 3: Generate Hyperledger org certificates
        generate_org_certificates('Hospital_A')
        generate_org_certificates('Hospital_B')

        print("Multi-hospital environment setup complete.")

    except Exception as e:
        print(f"Setup failed: {e}")


if __name__ == "__main__":
    setup_multi_hospital_environment()