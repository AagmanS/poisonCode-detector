"""Feature extraction for ML models."""

import ast
import re
import math
from typing import Dict
from collections import Counter

from pcd.dataflow import check_dataflow_pairs


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(code: str) -> Dict[str, float]:
    """
    Extract about 60 numeric features from code unit.
    
    Args:
        code: Python source code
        
    Returns:
        Dict of feature name -> value
    """
    features = {}
    
    # A. Dangerous API counts
    features['eval_count'] = code.count('eval(')
    features['exec_count'] = code.count('exec(')
    features['compile_count'] = code.count('compile(')
    features['__import___count'] = code.count('__import__')
    features['os_system_count'] = code.count('os.system')
    features['os_popen_count'] = code.count('os.popen')
    features['subprocess_count'] = code.count('subprocess')
    features['subprocess_shell_count'] = code.count('shell=True')
    features['socket_count'] = code.count('socket.')
    features['pty_spawn_count'] = code.count('pty.spawn')
    features['os_dup2_count'] = code.count('os.dup2')
    features['pickle_loads_count'] = code.count('pickle.loads') + code.count('pickle.load')
    features['marshal_loads_count'] = code.count('marshal.loads') + code.count('marshal.load')
    features['ctypes_count'] = code.count('ctypes')
    features['base64_decode_count'] = code.count('b64decode') + code.count('base64.decode')
    features['zlib_decompress_count'] = code.count('zlib.decompress')
    features['bytes_fromhex_count'] = code.count('bytes.fromhex')
    features['os_remove_count'] = code.count('os.remove')
    features['shutil_rmtree_count'] = code.count('shutil.rmtree')
    features['chmod_count'] = code.count('chmod')
    features['urlopen_count'] = code.count('urlopen')
    features['requests_post_count'] = code.count('requests.post')
    features['requests_get_count'] = code.count('requests.get')
    features['smtplib_count'] = code.count('smtplib')
    
    # B. Sensitive sources
    features['os_environ_count'] = code.count('os.environ') + code.count('getenv')
    features['ssh_access'] = int('.ssh' in code)
    features['aws_access'] = int('.aws' in code)
    features['passwd_access'] = int('passwd' in code)
    features['shadow_access'] = int('shadow' in code)
    features['bashrc_access'] = int('.bashrc' in code)
    features['crontab_access'] = int('crontab' in code)
    features['authorized_keys_access'] = int('authorized_keys' in code)
    features['login_data_access'] = int('Login Data' in code)
    features['getpass_count'] = code.count('getpass')
    
    # C. Source-to-sink dataflow
    dataflow_features = check_dataflow_pairs(code)
    features.update(dataflow_features)
    
    # D. Obfuscation indicators
    strings = re.findall(r'["\']([^"\']+)["\']', code)
    if strings:
        features['max_string_entropy'] = max(calculate_entropy(s) for s in strings)
        features['mean_string_entropy'] = sum(calculate_entropy(s) for s in strings) / len(strings)
        features['longest_string_length'] = max(len(s) for s in strings)
        
        # Base64-like strings (rough heuristic)
        features['base64_like_strings'] = sum(1 for s in strings 
                                              if len(s) > 20 and 
                                              re.match(r'^[A-Za-z0-9+/=]+$', s))
        # Hex-like strings
        features['hex_like_strings'] = sum(1 for s in strings 
                                           if len(s) > 10 and 
                                           re.match(r'^[0-9a-fA-F]+$', s))
    else:
        features['max_string_entropy'] = 0
        features['mean_string_entropy'] = 0
        features['longest_string_length'] = 0
        features['base64_like_strings'] = 0
        features['hex_like_strings'] = 0
    
    features['chr_count'] = code.count('chr(')
    features['join_count'] = code.count('.join(')
    features['chr_join_together'] = int('chr(' in code and '.join(' in code)
    
    # Identifier length stats (simple approximation)
    identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
    if identifiers:
        short_ids = [i for i in identifiers if len(i) <= 2]
        features['short_identifier_ratio'] = len(short_ids) / len(identifiers)
    else:
        features['short_identifier_ratio'] = 0
    
    features['getattr_count'] = code.count('getattr')
    features['getattr_dynamic'] = int('getattr' in code and ('builtin' in code.lower() or '+' in code))
    
    # E. Unicode indicators
    features['bidi_char_count'] = sum(code.count(c) for c in 
                                      ['\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                                       '\u2066', '\u2067', '\u2068', '\u2069'])
    features['zero_width_char_count'] = sum(code.count(c) for c in 
                                            ['\u200b', '\u200c', '\u200d', '\ufeff'])
    features['non_ascii_identifier_count'] = len([c for c in code if not c.isascii() and c.isalpha()])
    features['mixed_script_line_count'] = sum(1 for line in code.split('\n')
                                              if any(not c.isascii() and c.isalpha() for c in line)
                                              and any(c.isascii() and c.isalpha() for c in line))
    
    # F. Structural features
    lines = code.split('\n')
    features['line_count'] = len(lines)
    features['non_empty_line_count'] = len([l for l in lines if l.strip()])
    
    try:
        tree = ast.parse(code)
        features['ast_node_count'] = len(list(ast.walk(tree)))
        
        # Max nesting depth
        max_depth = 0
        for node in ast.walk(tree):
            depth = 0
            parent = node
            while hasattr(parent, '_parent'):
                depth += 1
                parent = parent._parent
            max_depth = max(max_depth, depth)
        features['max_nesting_depth'] = max_depth
        
        # Cyclomatic complexity (simplified: count decision points)
        complexity = 1  # Base
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        features['cyclomatic_complexity'] = complexity
        
        # Swallow-all except blocks
        swallow_count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None or (isinstance(node.type, ast.Name) and node.type.id == 'Exception'):
                    if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                        swallow_count += 1
        features['swallow_all_except_count'] = swallow_count
        
        # Hardcoded literal comparisons in auth-like functions
        auth_hardcoded_compare = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name.lower()
                if any(kw in func_name for kw in ['auth', 'login', 'check', 'verify']):
                    for subnode in ast.walk(node):
                        if isinstance(subnode, ast.Compare):
                            if any(isinstance(comp, ast.Constant) for comp in subnode.comparators):
                                auth_hardcoded_compare += 1
        features['auth_hardcoded_compare'] = auth_hardcoded_compare
        
        features['parse_ok'] = 1
    except:
        features['ast_node_count'] = 0
        features['max_nesting_depth'] = 0
        features['cyclomatic_complexity'] = 0
        features['swallow_all_except_count'] = 0
        features['auth_hardcoded_compare'] = 0
        features['parse_ok'] = 0
    
    # G. Meta features
    features['is_module_level'] = 0  # Will be set by caller
    features['has_main_guard'] = int('__main__' in code)
    
    # Check function name keywords
    func_name_lower = code.lower()
    features['has_auth_keyword'] = int(any(kw in func_name_lower for kw in ['auth', 'login']))
    features['has_update_keyword'] = int('update' in func_name_lower)
    features['has_sync_keyword'] = int('sync' in func_name_lower)
    
    # Date/time guarded destructive calls
    has_datetime = any(x in code for x in ['datetime', 'time.time'])
    has_destructive = any(x in code for x in ['os.remove', 'shutil.rmtree', 'unlink'])
    features['time_guarded_destruction'] = int(has_datetime and has_destructive)
    
    return features
