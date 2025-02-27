import json
import base64
import binascii
import logging
from pathlib import Path
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Any, List, Optional

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('MockBlockchain')


class MockBlockchain:
    def __init__(self, org_id: str):
        """Initialize the mock blockchain for the given organization."""
        self.org_id = org_id
        self.blockchain_dir = Path("blockchain_data") / org_id
        self.chain: List[Dict[str, Any]] = []
        self.current_block: int = 0

        # Ensure blockchain directory exists
        self.blockchain_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized blockchain for organization: {org_id}")

        # Load existing chain
        self.load_chain()

        # Verify chain integrity
        self._verify_chain_integrity()

    def _verify_chain_integrity(self) -> bool:
        """Verify the integrity of the entire blockchain."""
        try:
            if not self.chain:
                logger.info("Empty blockchain - integrity check passed")
                return True

            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]

                # Verify block hash
                if current_block["previous_hash"] != previous_block["hash"]:
                    logger.error(f"Chain integrity error at block {i}: Invalid previous hash")
                    return False

                # Verify block index
                if current_block["index"] != previous_block["index"] + 1:
                    logger.error(f"Chain integrity error at block {i}: Invalid block index")
                    return False

                # Verify current block's hash
                calculated_hash = self.__calculate_hash(current_block)
                if calculated_hash != current_block["hash"]:
                    logger.error(f"Chain integrity error at block {i}: Invalid block hash")
                    return False

            logger.info("Blockchain integrity verification passed")
            return True

        except Exception as e:
            logger.error(f"Chain integrity verification failed: {e}")
            return False

    def store_record(self, record: Dict[str, Any]) -> int:
        """Store a record in the blockchain by creating a new block."""
        try:
            logger.info("Starting to store new record in blockchain")

            # Validate record
            if not self._validate_record(record):
                raise ValueError("Invalid record format")

            # Prepare the record
            serializable_record = self.__prepare_record(record)
            logger.debug(f"Prepared record: {serializable_record}")

            # Create new block
            previous_hash = self.chain[-1]["hash"] if self.chain else "0" * 64
            new_block = {
                "index": self.current_block,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": serializable_record,
                "previous_hash": previous_hash,
                "session_id": record["session_id"]
            }

            # Calculate and add block hash
            new_block["hash"] = self.__calculate_hash(new_block)
            logger.debug(f"Created new block with hash: {new_block['hash']}")

            # Save block to file first
            self.__save_block_to_file(new_block)
            logger.info(f"Saved block {new_block['index']} to file")

            # Append to chain if file save was successful
            self.chain.append(new_block)
            block_index = self.current_block
            self.current_block += 1

            # Verify the new block
            if not self._verify_block(new_block):
                raise ValueError("Block verification failed")

            logger.info(f"Successfully added block {block_index} to chain")
            return block_index

        except Exception as e:
            logger.error(f"Failed to store record: {e}")
            raise

    def _validate_record(self, record: Dict[str, Any]) -> bool:
        """Validate record structure and required fields."""
        try:
            # Check required fields
            required_fields = {"session_id"}
            if not required_fields.issubset(record.keys()):
                logger.error(f"Missing required fields. Required: {required_fields}")
                return False

            # Validate session_id format
            if not isinstance(record["session_id"], str) or not record["session_id"].strip():
                logger.error("Invalid session_id format")
                return False

            return True

        except Exception as e:
            logger.error(f"Record validation failed: {e}")
            return False

    def _verify_block(self, block: Dict[str, Any]) -> bool:
        """Verify a single block's integrity."""
        try:
            # Verify required fields
            required_fields = {"index", "timestamp", "data", "previous_hash", "hash", "session_id"}
            if not required_fields.issubset(block.keys()):
                logger.error(f"Block missing required fields: {required_fields - block.keys()}")
                return False

            # Verify hash
            calculated_hash = self.__calculate_hash(block)
            if calculated_hash != block["hash"]:
                logger.error("Block hash verification failed")
                return False

            # If not genesis block, verify previous hash
            if block["index"] > 0:
                previous_block = self.chain[block["index"] - 1]
                if block["previous_hash"] != previous_block["hash"]:
                    logger.error("Previous hash verification failed")
                    return False

            return True

        except Exception as e:
            logger.error(f"Block verification failed: {e}")
            return False

    def get_record(self, block_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a record from the blockchain by its block index."""
        try:
            if block_id < 0 or block_id >= len(self.chain):
                logger.error(f"Block ID {block_id} out of range")
                return None

            block = self.chain[block_id]
            if self._verify_block(block):
                return block["data"]
            else:
                logger.error(f"Block {block_id} failed verification")
                return None

        except Exception as e:
            logger.error(f"Failed to retrieve record: {e}")
            return None

    def load_chain(self):
        """Load the blockchain from local files."""
        try:
            logger.info("Loading blockchain from files...")
            block_files = sorted(self.blockchain_dir.glob("block_*.json"))
            self.chain = []

            for block_file in block_files:
                try:
                    with block_file.open("r", encoding="utf-8") as f:
                        block = json.load(f)

                    if self._verify_block(block):
                        self.chain.append(block)
                        logger.debug(f"Loaded block {block['index']}")
                    else:
                        logger.error(f"Failed to verify block in {block_file}")

                except Exception as e:
                    logger.error(f"Error loading block from {block_file}: {e}")

            if self.chain:
                self.current_block = self.chain[-1]["index"] + 1

            logger.info(f"Loaded {len(self.chain)} blocks. Current block index: {self.current_block}")

        except Exception as e:
            logger.error(f"Failed to load blockchain: {e}")
            raise

    def __prepare_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a record for JSON serialization."""

        def encode_value(value: Any) -> Any:
            if isinstance(value, bytes):
                try:
                    return {
                        "base64": base64.b64encode(value).decode("utf-8"),
                        "hex": binascii.hexlify(value).decode("utf-8")
                    }
                except Exception as e:
                    raise ValueError(f"Error encoding binary data: {e}")
            elif isinstance(value, dict):
                return {k: encode_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [encode_value(v) for v in value]
            else:
                return value

        return {k: encode_value(v) for k, v in record.items()}

    def __save_block_to_file(self, block: Dict[str, Any]):
        """Save a block to a JSON file."""
        try:
            file_path = self.blockchain_dir / f"block_{block['index']}.json"
            file_path.write_text(json.dumps(block, indent=2), encoding="utf-8")
            logger.debug(f"Saved block to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save block to file: {e}")
            raise

    def __calculate_hash(self, block: Dict[str, Any]) -> str:
        """Calculate block hash."""
        block_copy = block.copy()
        block_copy.pop("hash", None)
        block_string = json.dumps(block_copy, sort_keys=True).encode("utf-8")
        return sha256(block_string).hexdigest()

    def get_chain_details(self) -> List[Dict[str, Any]]:
        """Get blockchain details for inspection."""
        return self.chain