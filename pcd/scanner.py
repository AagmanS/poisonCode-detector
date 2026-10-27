"""File discovery and unit splitting."""

import os
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass

from pcd.parsing import safe_parse, extract_functions, get_module_level_code


@dataclass
class CodeUnit:
    """A unit of code (function or module-level)."""
    name: str
    code: str
    start_line: int
    end_line: int
    is_module_level: bool
    file_path: str


@dataclass
class ScanFile:
    """A scanned Python file."""
    path: str
    units: List[CodeUnit]
    parse_ok: bool
    original_code: str


def discover_python_files(target: str, ignore_patterns: Optional[List[str]] = None) -> List[str]:
    """
    Discover Python files recursively, skipping ignored directories.
    
    Args:
        target: File path or directory path
        ignore_patterns: List of glob patterns to ignore
        
    Returns:
        List of Python file paths
    """
    ignore_patterns = ignore_patterns or [
        "**/.git/**", "**/venv/**", "**/node_modules/**", "**/__pycache__/**"
    ]
    
    target_path = Path(target)
    
    if target_path.is_file():
        return [str(target_path)] if target_path.suffix == '.py' else []
    
    # Directory - scan recursively
    python_files = []
    for root, dirs, files in os.walk(target):
        # Filter out ignored directories
        root_path = Path(root)
        skip = False
        for pattern in ignore_patterns:
            if any(part in ['.git', 'venv', 'node_modules', '__pycache__'] 
                   for part in root_path.parts):
                skip = True
                break
        
        if skip:
            dirs.clear()  # Don't recurse into subdirectories
            continue
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(str(root_path / file))
    
    return python_files


def split_into_units(code: str, file_path: str) -> Tuple[List[CodeUnit], bool]:
    """
    Split a Python file into units (each function/method + one module-level unit).
    
    Args:
        code: Python source code
        file_path: Path to the file
        
    Returns:
        Tuple of (list of CodeUnits, parse_ok)
    """
    parse_result = safe_parse(code, file_path)
    units = []
    
    if parse_result.parse_ok and parse_result.tree:
        # Extract functions
        functions = extract_functions(parse_result.tree)
        code_lines = code.split('\n')
        
        for func_name, func_node, start_line, end_line in functions:
            # Extract function code
            func_code = '\n'.join(code_lines[start_line - 1:end_line])
            units.append(CodeUnit(
                name=func_name,
                code=func_code,
                start_line=start_line,
                end_line=end_line,
                is_module_level=False,
                file_path=file_path
            ))
        
        # Extract module-level code
        module_code, start, end = get_module_level_code(parse_result.tree, code_lines)
        if module_code.strip():
            units.append(CodeUnit(
                name="<module>",
                code=module_code,
                start_line=start,
                end_line=end,
                is_module_level=True,
                file_path=file_path
            ))
    else:
        # Parse failed - treat entire file as one unit
        units.append(CodeUnit(
            name="<module>",
            code=code,
            start_line=1,
            end_line=len(code.split('\n')),
            is_module_level=True,
            file_path=file_path
        ))
    
    return units, parse_result.parse_ok


def scan_file(file_path: str) -> ScanFile:
    """
    Scan a single Python file and split it into units.
    
    Args:
        file_path: Path to Python file
        
    Returns:
        ScanFile object
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        # Return empty scan result on read error
        return ScanFile(
            path=file_path,
            units=[],
            parse_ok=False,
            original_code=""
        )
    
    units, parse_ok = split_into_units(code, file_path)
    
    return ScanFile(
        path=file_path,
        units=units,
        parse_ok=parse_ok,
        original_code=code
    )


def scan_target(target: str, ignore_patterns: Optional[List[str]] = None) -> List[ScanFile]:
    """
    Scan a file or directory target.
    
    Args:
        target: File path, directory path, or '-' for stdin
        ignore_patterns: Patterns to ignore
        
    Returns:
        List of ScanFile objects
    """
    if target == '-':
        # Read from stdin
        import sys
        code = sys.stdin.read()
        units, parse_ok = split_into_units(code, "<stdin>")
        return [ScanFile(
            path="<stdin>",
            units=units,
            parse_ok=parse_ok,
            original_code=code
        )]
    
    files = discover_python_files(target, ignore_patterns)
    return [scan_file(f) for f in files]
