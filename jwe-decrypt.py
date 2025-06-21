#!/usr/bin/env python3

import argparse
import yaml
import sys
import base64
import json
import logging
from pathlib import Path
from jwcrypto import jwk, jwe

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# --- Argument Parsing ---
def parse_args():
    parser = argparse.ArgumentParser(
        description="Decrypt a JWE token using a symmetric key from YAML config or prompt."
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=None,
        help="Path to YAML config file. If omitted, will prompt for input."
    )
    parser.add_argument(
        "--claims", action="store_true",
        help="Parse decrypted JWT payload into JSON claims"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug logging"
    )
    return parser.parse_args()

# --- Config Loader ---
def load_config(path):
    try:
        logger.info(f"Loading config from {path}")
        with path.open('r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to read config file: {e}")
        sys.exit(1)

# --- Helpers ---
def safe_b64decode(data):
    data = data.strip().replace('\n', '').replace(' ', '')
    padded = data + '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)

# --- Decryption Logic ---
def decrypt_jwe(token_str, key_str):
    logger.debug("Sanitizing and decoding key...")
    raw_key = safe_b64decode(key_str)
    encoded_key = base64.urlsafe_b64encode(raw_key).decode()
    jwk_key = jwk.JWK(kty='oct', k=encoded_key)

    logger.debug("Parsing and decrypting JWE token...")
    token = jwe.JWE()
    token.deserialize(token_str)
    token.decrypt(jwk_key)

    return token.payload.decode()

# --- Prompt Fallback ---
def prompt_for_input():
    print("\n🔐 Enter the base64url-encoded symmetric key:")
    key = input("> ").strip()
    print("\n🔓 Paste the full encrypted JWE token (then press Ctrl+D or Enter twice):")
    token = sys.stdin.read().strip()
    return {'key': key, 'token': token}

# --- JWT Parser ---
def pretty_print_claims(jwt_token):
    try:
        header_b64, payload_b64, *_ = jwt_token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

        logger.info("🔍 JWT Header:")
        print(json.dumps(header, indent=2))
        logger.info("📜 JWT Claims:")
        print(json.dumps(payload, indent=2))
    except Exception as e:
        logger.warning(f"Failed to parse JWT: {e}. Showing raw payload.")
        print(jwt_token)

# --- Main Logic ---
def main():
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    config = (
        load_config(args.config)
        if args.config
        else prompt_for_input()
    )

    token_str = config.get("token")
    key_str = config.get("key")

    if not token_str or not key_str:
        logger.error("Both 'token' and 'key' must be provided.")
        sys.exit(1)

    try:
        payload = decrypt_jwe(token_str, key_str)
        logger.info("✅ Decryption successful!")
        logger.info("🪪 Decrypted JWT Token:")
        logger.info(payload)  # <-- JWT token (header.payload.signature)
        if args.claims:
            pretty_print_claims(payload)
        else:
            print(payload)
    except Exception as e:
        logger.error(f"❌ Failed to decrypt token: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
