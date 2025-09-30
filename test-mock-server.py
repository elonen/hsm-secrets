#!/usr/bin/env python3
"""
Mock HTTP server for testing hsm-secrets.
Handles certificate submission and provides mock CRL responses.
"""

import os
import sys
import time
import threading
import json
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone


"""
This is a mock HTTP server for testing hsm-secrets. It mocks:
 - Certificate submission endpoint (accepts any cert)
 - CRL endpoint (returns a minimal valid CRL)

It tracks uploaded certificates in memory and can return a list of uploads
for test code to assert against.
"""


class MockServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock server."""

    # Shared state for tracking uploads across requests
    uploads = []

    def log_message(self, format, *args):
        """Suppress default logging to keep test output clean."""
        pass

    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)

        if parsed_path.path == '/api/upload':
            self._handle_cert_upload()
        elif parsed_path.path == '/api/reset':
            self._handle_reset_uploads()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)

        if parsed_path.path.startswith('/mock-crl/') and parsed_path.path.endswith('.crl'):
            self._handle_crl_request()
        elif parsed_path.path == '/api/uploads':
            self._handle_get_uploads()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def _handle_cert_upload(self):
        """Handle certificate upload requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        # Extract filename from multipart form data (simplified)
        filename = "unknown.pem"
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' in content_type:
            # Simple extraction - look for filename in the data
            post_str = post_data.decode('utf-8', errors='ignore')
            if 'filename=' in post_str:
                start = post_str.find('filename="') + 10
                end = post_str.find('"', start)
                if end > start:
                    filename = post_str[start:end]

        # Store upload record
        upload_record = {
            'filename': filename,
            'size': len(post_data),
            'timestamp': time.time(),
            'content_hash': hashlib.sha256(post_data).hexdigest()[:16]
        }
        MockServerHandler.uploads.append(upload_record)

        # Just accept any certificate upload
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Certificate received')

        # Log to stderr for debugging if needed
        print(f"[MOCK] Certificate upload: {filename} ({len(post_data)} bytes)", file=sys.stderr)

    def _handle_crl_request(self):
        """Handle CRL requests by returning a minimal valid CRL."""
        try:
            # Generate a minimal empty CRL
            crl_der = self._generate_empty_crl()

            self.send_response(200)
            self.send_header('Content-Type', 'application/pkix-crl')
            self.send_header('Content-Length', str(len(crl_der)))
            self.end_headers()
            self.wfile.write(crl_der)

            print(f"[MOCK] CRL request: {self.path}", file=sys.stderr)

        except Exception as e:
            print(f"[MOCK] Error generating CRL: {e}", file=sys.stderr)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    def _handle_get_uploads(self):
        """Handle requests to get upload history."""
        response_data = {
            'uploads': MockServerHandler.uploads,
            'count': len(MockServerHandler.uploads)
        }
        response_json = json.dumps(response_data, indent=2)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))

    def _handle_reset_uploads(self):
        """Handle requests to reset upload history."""
        MockServerHandler.uploads.clear()

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Upload history cleared')

        print(f"[MOCK] Upload history reset", file=sys.stderr)

    def _generate_empty_crl(self):
        """Generate a minimal valid empty CRL."""
        # Create a temporary key for signing the CRL
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create subject for the CRL issuer
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test Mock CA"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Mock CA"),
        ])

        # Build empty CRL
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=1))

        # Sign the CRL
        crl = builder.sign(private_key, hashes.SHA256())

        # Return DER-encoded CRL
        return crl.public_bytes(serialization.Encoding.DER)


def start_server(port=8693):
    """Start the mock server."""
    server = HTTPServer(('localhost', port), MockServerHandler)
    print(f"[MOCK] Starting server on localhost:{port}", file=sys.stderr)

    def run_server():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    # Give the server a moment to start
    time.sleep(0.1)

    return server


def stop_server(server):
    """Stop the mock server."""
    print("[MOCK] Stopping server", file=sys.stderr)
    server.shutdown()
    server.server_close()


if __name__ == '__main__':
    import signal

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8693
    server = start_server(port)

    def signal_handler(sig, frame):
        stop_server(server)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        print(f"Mock server running on localhost:{port}")
        print("Press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_server(server)