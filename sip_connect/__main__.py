import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path
base_dir = Path(__file__).parent
sys.path.append(str(base_dir))
sys.path.append(str(base_dir.parent))

from sip_connect.app import SIPApp  # Assuming you'll create this in app.py


def setup_logging(debug=False):
    """Configure logging for the application"""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('sip_service.log')
        ]
    )


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Quantum SIP Service')
    parser.add_argument('--org',
                        default='Hospital_A',
                        choices=['Hospital_A', 'Hospital_B'],
                        help='Organization to initialize')
    parser.add_argument('--debug',
                        action='store_true',
                        help='Enable debug logging')

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    setup_logging(args.debug)

    # Create and run the application
    try:
        app = SIPApp(args.org)
        app.initialize()
        app.run()
    except KeyboardInterrupt:
        print("\nSIP Service terminated by user.")
    except Exception as e:
        print(f"Fatal error in SIP Service: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()