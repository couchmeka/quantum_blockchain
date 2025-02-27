import os
import logging
from ctypes import CDLL, c_int, c_ubyte, POINTER, Structure, cast, Array

logger = logging.getLogger('KyberWrapper')

# Get the directory containing this script
dir_path = os.path.dirname(os.path.realpath(__file__))

# Correct the path to the Kyber shared library
kyber_lib_path = os.path.join(dir_path, 'kyber/ref/libpqcrystals_kyber512_ref.so')

# Verify the file exists
if not os.path.exists(kyber_lib_path):
    raise FileNotFoundError(f"Kyber library not found at {kyber_lib_path}")

try:
    kyber = CDLL(kyber_lib_path)
    logger.info("Successfully loaded Kyber shared library")
except OSError as e:
    raise OSError(f"Failed to load Kyber library: {e}")

# Constants for Kyber512
KYBER_PUBLICKEYBYTES = 800
KYBER_SECRETKEYBYTES = 1632
KYBER_CIPHERTEXTBYTES = 768
KYBER_SSBYTES = 32  # Shared secret bytes


# Define structures for passing arrays
class ByteArray(Structure):
    _fields_ = [("data", POINTER(c_ubyte))]


# Function prototypes
kyber.pqcrystals_kyber512_ref_keypair.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
kyber.pqcrystals_kyber512_ref_keypair.restype = c_int

kyber.pqcrystals_kyber512_ref_enc.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)]
kyber.pqcrystals_kyber512_ref_enc.restype = c_int

kyber.pqcrystals_kyber512_ref_dec.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)]
kyber.pqcrystals_kyber512_ref_dec.restype = c_int


def convert_kyber_key(key_data, expected_size):
    """Convert key data to proper Kyber format"""
    try:
        # If it's already a pointer type, return it
        if isinstance(key_data, POINTER(c_ubyte)):
            return key_data

        # Handle Array type
        if isinstance(key_data, Array):
            key_bytes = bytes(key_data)
            key_array = (c_ubyte * expected_size)(*key_bytes[:expected_size])
            return cast(key_array, POINTER(c_ubyte))

        # Handle bytes type
        if isinstance(key_data, bytes):
            key_array = (c_ubyte * expected_size)(*key_data[:expected_size])
            return cast(key_array, POINTER(c_ubyte))

        # Handle other types by converting to bytes first
        key_bytes = bytes(key_data)
        key_array = (c_ubyte * expected_size)(*key_bytes[:expected_size])
        return cast(key_array, POINTER(c_ubyte))

    except Exception as e:
        logger.error(f"Failed to convert Kyber key: {str(e)}")
        raise TypeError(f"Failed to convert Kyber key: {str(e)}")


def kyber_keygen():
    """Generate a Kyber keypair with proper type conversion"""
    try:
        # Create buffers with correct types
        public_key = (c_ubyte * KYBER_PUBLICKEYBYTES)()
        secret_key = (c_ubyte * KYBER_SECRETKEYBYTES)()

        # Get pointers
        public_key_ptr = cast(public_key, POINTER(c_ubyte))
        secret_key_ptr = cast(secret_key, POINTER(c_ubyte))

        # Call the keypair generation function
        ret = kyber.pqcrystals_kyber512_ref_keypair(public_key_ptr, secret_key_ptr)

        if ret != 0:
            raise Exception(f"Kyber keypair generation failed with error {ret}")

        # Return bytes directly instead of pointers
        return bytes(public_key), bytes(secret_key)

    except Exception as e:
        logger.error(f"Failed to generate Kyber keypair: {str(e)}")
        raise


def kyber_encap(public_key):
    """Encapsulate with proper type conversion"""
    try:
        # Convert public key to proper format
        pub_key_ptr = convert_kyber_key(public_key, KYBER_PUBLICKEYBYTES)

        # Create output buffers
        ciphertext = (c_ubyte * KYBER_CIPHERTEXTBYTES)()
        shared_secret = (c_ubyte * KYBER_SSBYTES)()

        ret = kyber.pqcrystals_kyber512_ref_enc(
            cast(ciphertext, POINTER(c_ubyte)),
            cast(shared_secret, POINTER(c_ubyte)),
            pub_key_ptr,
            None
        )

        if ret != 0:
            raise Exception("Kyber encapsulation failed")

        return bytes(shared_secret), bytes(ciphertext)

    except Exception as e:
        logger.error(f"Failed to encapsulate: {str(e)}")
        raise


def kyber_decap(ciphertext, secret_key):
    """Decapsulate a shared secret using a ciphertext and secret key"""
    try:
        # Convert inputs to proper format
        ct_ptr = convert_kyber_key(ciphertext, KYBER_CIPHERTEXTBYTES)
        sk_ptr = convert_kyber_key(secret_key, KYBER_SECRETKEYBYTES)

        # Create shared secret buffer
        shared_secret = (c_ubyte * KYBER_SSBYTES)()
        ss_ptr = cast(shared_secret, POINTER(c_ubyte))

        ret = kyber.pqcrystals_kyber512_ref_dec(
            ss_ptr,
            ct_ptr,
            sk_ptr
        )

        if ret != 0:
            raise Exception("Kyber decapsulation failed")

        return bytes(shared_secret)

    except Exception as e:
        logger.error(f"Failed to decapsulate: {str(e)}")
        raise


def test_kyber():
    """Test the Kyber implementation"""
    try:
        print("Testing Kyber key generation...")
        public_key, private_key = kyber_keygen()

        print(f"Public key length: {len(public_key)}")
        print(f"Private key length: {len(private_key)}")

        # Test key lengths
        assert len(public_key) == KYBER_PUBLICKEYBYTES
        assert len(private_key) == KYBER_SECRETKEYBYTES

        # Create ciphertext and shared secrets
        shared_secret1, ciphertext = kyber_encap(public_key)
        shared_secret2 = kyber_decap(ciphertext, private_key)

        if shared_secret1 == shared_secret2:
            print("Kyber key exchange successful!")
            return True
        else:
            print("Kyber key exchange failed!")
            return False

    except Exception as e:
        print(f"Kyber test failed: {str(e)}")
        return False


if __name__ == "__main__":
    test_kyber()