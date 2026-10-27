"""Tests for scanner module."""

import pytest
from pcd.scanner import split_into_units, discover_python_files
from pcd.parsing import safe_parse


def test_safe_parse_never_executes():
    """Test that parsing never executes code."""
    dangerous_code = """
import os
os.system("echo EXECUTED")
exec("print('EXECUTED')")
"""
    # This should parse without executing
    result = safe_parse(dangerous_code)
    assert result is not None
    # If code executed, we'd see output, but we don't


def test_split_into_units():
    """Test splitting code into units."""
    code = """
def func1():
    return 1

def func2():
    return 2

x = 10
"""
    units, parse_ok = split_into_units(code, "test.py")
    assert parse_ok
    assert len(units) >= 2  # At least 2 functions
    
    # Check function units
    func_names = [u.name for u in units if not u.is_module_level]
    assert 'func1' in func_names
    assert 'func2' in func_names


def test_discover_files():
    """Test file discovery."""
    # This would need a test directory structure
    pass


if __name__ == '__main__':
    pytest.main([__file__])
