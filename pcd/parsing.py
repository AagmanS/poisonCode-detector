"""Safe parsing of Python source code using AST."""

import ast
import tokenize
from io import StringIO
from typing import Optional, Union, List, Tuple


class ParseResult:
    """Result of parsing a Python source file."""
    
    def __init__(self, tree: Optional[ast.AST], parse_ok: bool, tokens: Optional[List] = None):
        self.tree = tree
        self.parse_ok = parse_ok
        self.tokens = tokens or []


def safe_parse(code: str, filename: str = "<unknown>") -> ParseResult:
    """
    Parse Python code using ast.parse. Never import, exec, or run the code.
    On SyntaxError, fall back to token-level analysis.
    
    Args:
        code: Python source code string
        filename: Name of the file being parsed
        
    Returns:
        ParseResult with tree and parse_ok status
    """
    try:
        tree = ast.parse(code, filename=filename)
        return ParseResult(tree=tree, parse_ok=True)
    except SyntaxError:
        # Fall back to token-level analysis
        tokens = []
        try:
            tokens = list(tokenize.generate_tokens(StringIO(code).readline))
        except tokenize.TokenError:
            pass  # Best effort
        return ParseResult(tree=None, parse_ok=False, tokens=tokens)


def extract_functions(tree: ast.AST) -> List[Tuple[str, ast.FunctionDef, int, int]]:
    """
    Extract all function and method definitions from an AST.
    
    Args:
        tree: AST tree
        
    Returns:
        List of (name, node, start_line, end_line) tuples
    """
    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_line = node.lineno
            # Find end line by looking at the last statement
            end_line = node.lineno
            if node.body:
                last_stmt = node.body[-1]
                end_line = getattr(last_stmt, 'end_lineno', last_stmt.lineno)
            functions.append((node.name, node, start_line, end_line))
    return functions


def get_module_level_code(tree: ast.AST, code_lines: List[str]) -> Tuple[str, int, int]:
    """
    Extract module-level code (everything outside functions/classes).
    
    Args:
        tree: AST tree
        code_lines: List of code lines
        
    Returns:
        Tuple of (code, start_line, end_line)
    """
    # Get all function and class line ranges
    excluded_lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno
            end = node.lineno
            if node.body:
                last_stmt = node.body[-1]
                end = getattr(last_stmt, 'end_lineno', last_stmt.lineno)
            for i in range(start, end + 1):
                excluded_lines.add(i)
    
    # Collect module-level lines
    module_lines = []
    for i, line in enumerate(code_lines, start=1):
        if i not in excluded_lines:
            module_lines.append(line)
    
    module_code = '\n'.join(module_lines)
    return module_code, 1, len(code_lines)


def normalize_code_for_tokens(code: str) -> str:
    """
    Normalize code for token-based model:
    - Replace strings longer than 40 chars with <LONGSTR>
    - Replace numbers with <NUM>
    - Keep API and attribute names
    - Drop comments
    
    Args:
        code: Python source code
        
    Returns:
        Normalized code string
    """
    try:
        tokens = list(tokenize.generate_tokens(StringIO(code).readline))
        result = []
        
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                continue  # Drop comments
            elif tok.type == tokenize.STRING:
                # Replace long strings
                if len(tok.string) > 40:
                    result.append('<LONGSTR>')
                else:
                    result.append(tok.string)
            elif tok.type == tokenize.NUMBER:
                result.append('<NUM>')
            else:
                result.append(tok.string)
        
        return ''.join(result)
    except (tokenize.TokenError, Exception):
        # Fall back to simple replacement
        lines = []
        for line in code.split('\n'):
            if '#' in line:
                line = line[:line.index('#')]
            lines.append(line)
        return '\n'.join(lines)
