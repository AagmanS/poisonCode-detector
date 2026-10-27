"""Build gate and compile integration."""

import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from pcd.report import ScanReport


def execute_build_command(command: List[str], cwd: Optional[str] = None) -> int:
    """
    Execute the build command.
    
    Args:
        command: Command and arguments
        cwd: Working directory
        
    Returns:
        Exit code from command
    """
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=False,
            text=True
        )
        return result.returncode
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return 3


def build_gate(report: ScanReport, 
               build_command: Optional[List[str]] = None,
               fail_on: str = "malicious") -> int:
    """
    Gate logic for build command.
    
    Args:
        report: Scan report
        build_command: Build command to execute if allowed
        fail_on: 'malicious' or 'suspicious'
        
    Returns:
        Exit code: 0 clean, 1 suspicious, 2 malicious, 3 error
    """
    # Determine exit code based on verdict
    if report.verdict == "MALICIOUS":
        exit_code = 2
    elif report.verdict == "SUSPICIOUS":
        exit_code = 1
    else:
        exit_code = 0
    
    # Execute build command if gate allows
    if report.gate_decision == "ALLOW":
        if build_command:
            return execute_build_command(build_command)
        return 0
    elif report.gate_decision == "WARN":
        if build_command:
            build_exit = execute_build_command(build_command)
            return build_exit if build_exit != 0 else 1
        return 1
    else:  # BLOCK
        if build_command:
            print("\nBuild blocked due to malicious code detected.", file=sys.stderr)
        return 2


def compile_python_file(file_path: str) -> int:
    """
    Compile a Python file using py_compile.
    
    Args:
        file_path: Path to Python file
        
    Returns:
        Exit code: 0 success, 3 error
    """
    import py_compile
    
    try:
        py_compile.compile(file_path, doraise=True)
        print(f"Compiled: {file_path}")
        return 0
    except py_compile.PyCompileError as e:
        print(f"Compile error: {e}", file=sys.stderr)
        return 3
