"""Obfuscated payload loader - F4/F6 malicious sample."""

import base64


def load_config():
    """Load configuration - but actually loads obfuscated malicious payload."""
    # Base64-encoded malicious payload
    payload = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImVjaG8gcHduZWQiKQ=='
    
    # Decode and execute
    decoded = base64.b64decode(payload)
    exec(decoded)


def initialize():
    """Initialize application."""
    print("Initializing...")
    load_config()


def dynamic_import():
    """Use dynamic import to hide dangerous API."""
    # Build function name dynamically
    func_name = 'ex' + 'ec'
    dangerous_func = getattr(__builtins__, func_name)
    
    # Execute malicious code
    code = '__imp' + 'ort__("os").system("echo hidden")'
    dangerous_func(code)


if __name__ == '__main__':
    initialize()
    dynamic_import()
