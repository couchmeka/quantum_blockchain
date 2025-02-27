import logging
from ctypes import c_ubyte, POINTER, cast, c_char, Array, create_string_buffer
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger('KeyUtils')


# Keep existing conversion functions
def convert_to_ubyte_pointer(data):
    """Convert byte buffer to LP_c_ubyte for compatibility"""
    try:
        logger.debug(f"Input data type: {type(data)}")
        logger.debug(f"Input data length: {len(data) if hasattr(data, '__len__') else 'no length'}")

        # Handle c_char_Array case
        if isinstance(data, Array) and data._type_ == c_char:
            data_bytes = bytes(data)
            ubyte_array = (c_ubyte * len(data_bytes))(*data_bytes)
            return cast(ubyte_array, POINTER(c_ubyte))

        # Handle bytes case
        if isinstance(data, bytes):
            ubyte_array = (c_ubyte * len(data))(*data)
            return cast(ubyte_array, POINTER(c_ubyte))

        # Handle other cases
        if isinstance(data, (list, tuple)):
            data = bytes(data)
        elif isinstance(data, str):
            data = data.encode('utf-8')

        # Create array of correct size
        arr = (c_ubyte * len(data))(*data)

        # Cast to pointer
        ptr = cast(arr, POINTER(c_ubyte))
        logger.debug(f"Successfully cast to pointer: {ptr}")
        return ptr

    except Exception as e:
        logger.error(f"Failed to convert to ubyte pointer: {str(e)}", exc_info=True)
        raise TypeError(f"Failed to convert to ubyte pointer: {str(e)}")


def convert_kyber_key(key_data):
    """Special converter for Kyber keys"""
    try:
        if isinstance(key_data, c_char * 32):  # Kyber public key size
            key_bytes = bytes(key_data)
            key_array = (c_ubyte * 32)(*key_bytes)
            return cast(key_array, POINTER(c_ubyte))
        return convert_to_ubyte_pointer(key_data)
    except Exception as e:
        logger.error(f"Failed to convert Kyber key: {str(e)}", exc_info=True)
        raise TypeError(f"Failed to convert Kyber key: {str(e)}")


# Add new key management class
class KeyManager:
    def __init__(self, org_id: str, base_path: str = "/app"):
        self.org_id = org_id
        self.base_path = Path(base_path)

        # Use absolute path to /app/keys
        self.keys_dir = self.base_path / "keys"

        # Ensure directory exists
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    def get_key_path(self, key_type: str) -> Path:
        """Get the standardized path for a specific key type"""
        # Match the exact filenames from the filesystem
        key_paths = {
            'falcon_public': self.keys_dir / f"{self.org_id}_falcon_public.key",
            'falcon_private': self.keys_dir / f"{self.org_id}_falcon_private.key",
            'kyber_public': self.keys_dir / f"{self.org_id}_kyber_public.key",
            'kyber_private': self.keys_dir / f"{self.org_id}_kyber_private.key"
        }
        return key_paths.get(key_type)

    def load_key(self, key_type: str) -> Optional[bytes]:
        """Load a specific key with proper error handling"""
        try:
            key_path = self.get_key_path(key_type)
            if not key_path or not key_path.exists():
                logger.error(f"Key file not found: {key_path}")
                return None

            with open(key_path, 'rb') as f:
                key_data = f.read()

            if not key_data:
                logger.error(f"Empty key file: {key_path}")
                return None

            logger.debug(f"Successfully loaded key: {key_type}")
            return key_data

        except Exception as e:
            logger.error(f"Error loading {key_type}: {e}")
            return None

    def load_all_keys(self) -> Dict[str, bytes]:
        """Load all keys for an organization"""
        keys = {}
        for key_type in ['falcon_public', 'falcon_private', 'kyber_public', 'kyber_private']:
            key_data = self.load_key(key_type)
            if key_data:
                keys[key_type] = key_data
        return keys


# Add convenience function for conversion and loading
def load_and_convert_keys(org_id: str, base_path: str = "/app") -> Dict[str, Any]:
    """Load and convert keys to the correct format"""
    try:
        key_manager = KeyManager(org_id, base_path)

        # Get paths to key files
        falcon_public_path = key_manager.get_key_path('falcon_public')
        falcon_private_path = key_manager.get_key_path('falcon_private')
        kyber_public_path = key_manager.get_key_path('kyber_public')
        kyber_private_path = key_manager.get_key_path('kyber_private')

        # Read keys as raw bytes
        falcon_public = None
        falcon_private = None
        kyber_public = None
        kyber_private = None

        if falcon_public_path and falcon_public_path.exists():
            with open(falcon_public_path, 'rb') as f:
                falcon_public = f.read()

        if falcon_private_path and falcon_private_path.exists():
            with open(falcon_private_path, 'rb') as f:
                falcon_private = f.read()

        if kyber_public_path and kyber_public_path.exists():
            with open(kyber_public_path, 'rb') as f:
                kyber_public = f.read()

        if kyber_private_path and kyber_private_path.exists():
            with open(kyber_private_path, 'rb') as f:
                kyber_private = f.read()

        # Create dictionary of keys
        if not all([falcon_public, falcon_private, kyber_public, kyber_private]):
            logger.error(f"Failed to load one or more keys for {org_id}")
            raise ValueError("Missing key files")

        # Return keys directly as bytes, not pointers
        return {
            'falcon_public': falcon_public,
            'falcon_private': falcon_private,
            'kyber_public': kyber_public,
            'kyber_private': kyber_private
        }

    except Exception as e:
        logger.error(f"Failed to load and convert keys: {e}")
        raise
