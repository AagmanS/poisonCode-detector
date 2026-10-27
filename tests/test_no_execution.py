"""Test that scanner never executes scanned code."""

import pytest
import os
import tempfile
from pcd.scanner import scan_file


def test_scanner_never_executes_code():
    """Verify that scanning never executes the code being scanned."""
    # Create a temp file with code that would create a marker if executed
    marker_file = tempfile.mktemp(suffix='.marker')
    
    dangerous_code = f"""
# This code should never execute during scanning
import os

# If this runs, it will create a marker file
with open('{marker_file}', 'w') as f:
    f.write('EXECUTED')

def dangerous_function():
    with open('{marker_file}', 'w') as f:
        f.write('EXECUTED')
    os.system("echo EXECUTED")
"""
    
    # Write to temp Python file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(dangerous_code)
        temp_py_file = f.name
    
    try:
        # Scan the file
        scan_result = scan_file(temp_py_file)
        
        # Check that marker file was NOT created
        assert not os.path.exists(marker_file), \
            "Scanner executed the scanned code! This is a security violation."
        
        # Verify we got a result
        assert scan_result is not None
        assert len(scan_result.units) > 0
        
    finally:
        # Cleanup
        os.unlink(temp_py_file)
        if os.path.exists(marker_file):
            os.unlink(marker_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
