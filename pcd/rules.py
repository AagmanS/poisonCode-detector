"""Rule engine for detecting malicious patterns."""

import ast
import re
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class RuleMatch:
    """A rule match with evidence."""
    rule_id: str
    severity: str  # low, medium, high, critical
    line: int
    snippet: str
    why: str
    family: str  # F1-F10


# Rule patterns and detection logic
class RuleEngine:
    """Engine for applying detection rules to code."""
    
    def __init__(self):
        self.rules = self._init_rules()
    
    def _init_rules(self):
        """Initialize all detection rules."""
        return [
            # F1: Backdoor authentication
            self._check_hardcoded_auth_bypass,
            self._check_magic_credential,
            self._check_early_return_true,
            
            # F2: Data exfiltration
            self._check_sensitive_file_read,
            self._check_network_send,
            
            # F3: Reverse shell
            self._check_socket_subprocess,
            self._check_pty_spawn,
            
            # F4: Obfuscated loader
            self._check_base64_exec,
            self._check_decode_exec,
            
            # F5: Logic/time bomb
            self._check_time_based_destruction,
            self._check_date_guard,
            
            # F6: API hiding
            self._check_dynamic_import,
            self._check_getattr_builtin,
            self._check_chr_join_construction,
            
            # F7: Trojan Source
            self._check_bidi_characters,
            self._check_zero_width_chars,
            self._check_homoglyph_identifiers,
            
            # F8: Unsafe deserialization
            self._check_pickle_loads,
            self._check_marshal_loads,
            self._check_yaml_unsafe_load,
            
            # F9: Persistence
            self._check_crontab_modification,
            self._check_bashrc_modification,
            self._check_authorized_keys,
            
            # F10: Download and execute
            self._check_download_exec,
            self._check_chmod_exec,
        ]
    
    def check_code(self, code: str, start_line: int = 1) -> List[RuleMatch]:
        """
        Apply all rules to code and return matches.
        
        Args:
            code: Python source code
            start_line: Line number offset
            
        Returns:
            List of RuleMatch objects
        """
        matches = []
        for rule_func in self.rules:
            rule_matches = rule_func(code, start_line)
            matches.extend(rule_matches)
        return matches
    
    # F1: Backdoor authentication rules
    def _check_hardcoded_auth_bypass(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for hardcoded magic credentials in auth functions."""
        matches = []
        lines = code.split('\n')
        
        # Look for auth-related function names with hardcoded comparisons
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name_lower = node.name.lower()
                    if any(kw in func_name_lower for kw in ['auth', 'login', 'check', 'verify']):
                        # Check for hardcoded string comparisons
                        for subnode in ast.walk(node):
                            if isinstance(subnode, ast.Compare):
                                # Check if comparing to a string literal
                                if isinstance(subnode.left, ast.Name) and any(
                                    isinstance(comp, ast.Constant) and isinstance(comp.value, str)
                                    for comp in subnode.comparators
                                ):
                                    line_no = start_line + subnode.lineno - 1
                                    snippet = lines[subnode.lineno - 1][:120] if subnode.lineno <= len(lines) else ""
                                    matches.append(RuleMatch(
                                        rule_id="PC-F1-01",
                                        severity="critical",
                                        line=line_no,
                                        snippet=snippet.strip(),
                                        why="Hardcoded credential comparison in auth-like function",
                                        family="F1"
                                    ))
        except:
            pass
        
        return matches
    
    def _check_magic_credential(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for magic password/token patterns."""
        matches = []
        lines = code.split('\n')
        
        patterns = [
            (r'password\s*==\s*["\']', "Hardcoded password comparison"),
            (r'token\s*==\s*["\']', "Hardcoded token comparison"),
            (r'user\s*==\s*["\'].*admin', "Hardcoded admin user check"),
        ]
        
        for i, line in enumerate(lines):
            for pattern, reason in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append(RuleMatch(
                        rule_id="PC-F1-02",
                        severity="high",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why=reason,
                        family="F1"
                    ))
        
        return matches
    
    def _check_early_return_true(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for early return True in auth functions."""
        matches = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name_lower = node.name.lower()
                    if any(kw in func_name_lower for kw in ['auth', 'login', 'check']):
                        # Look for return True statements
                        for subnode in ast.walk(node):
                            if isinstance(subnode, ast.Return) and isinstance(subnode.value, ast.Constant):
                                if subnode.value.value is True:
                                    line_no = start_line + subnode.lineno - 1
                                    snippet = lines[subnode.lineno - 1][:120] if subnode.lineno <= len(lines) else ""
                                    matches.append(RuleMatch(
                                        rule_id="PC-F1-03",
                                        severity="medium",
                                        line=line_no,
                                        snippet=snippet.strip(),
                                        why="Early return True in auth function",
                                        family="F1"
                                    ))
        except:
            pass
        
        return matches
    
    # F2: Data exfiltration rules
    def _check_sensitive_file_read(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for reading sensitive files."""
        matches = []
        lines = code.split('\n')
        
        sensitive_paths = ['.ssh', '.aws', 'passwd', 'shadow', 'credentials', 
                          'authorized_keys', 'Login Data', '.bash_history']
        
        for i, line in enumerate(lines):
            for path in sensitive_paths:
                if path in line and ('open(' in line or 'read' in line):
                    matches.append(RuleMatch(
                        rule_id="PC-F2-01",
                        severity="high",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why=f"Reads a sensitive credential file ({path})",
                        family="F2"
                    ))
                    break
        
        return matches
    
    def _check_network_send(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for network send operations - only flag if combined with sensitive data."""
        matches = []
        
        # Only flag if there's BOTH network send AND sensitive file access in same unit
        has_sensitive = any(x in code for x in ['.ssh', '.aws', 'passwd', 'shadow',
                                                 'credentials', 'authorized_keys', 'getpass'])
        has_network_write = any(x in code for x in ['requests.post', 'requests.put', 
                                                     'socket.send', 'smtplib'])
        
        if has_sensitive and has_network_write:
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if any(api in line for api in ['requests.post', 'requests.put', 'socket.send']):
                    matches.append(RuleMatch(
                        rule_id="PC-F2-02",
                        severity="critical",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="Sensitive value flows to a network sink",
                        family="F2"
                    ))
                    break
        
        return matches
    
    # F3: Reverse shell rules
    def _check_socket_subprocess(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for socket + subprocess combination - requires shell wiring."""
        matches = []
        
        # Look for actual reverse shell pattern: socket connect + shell wiring
        has_socket_connect = 'socket' in code and ('connect(' in code or 's.connect' in code)
        has_shell_wiring = any(x in code for x in ['fileno()', 'os.dup2', 'pty.spawn'])
        has_shell = any(x in code for x in ['/bin/sh', '/bin/bash', 'cmd.exe'])
        
        # Only flag if we have clear reverse shell pattern
        if has_socket_connect and (has_shell_wiring or has_shell):
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if 'socket' in line or 'fileno' in line or 'dup2' in line or 'pty.spawn' in line:
                    matches.append(RuleMatch(
                        rule_id="PC-F3-01",
                        severity="critical",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="Socket wired to shell (reverse shell indicator)",
                        family="F3"
                    ))
                    break
        
        return matches
    
    def _check_pty_spawn(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for pty.spawn usage."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'pty.spawn' in line or 'os.dup2' in line:
                matches.append(RuleMatch(
                    rule_id="PC-F3-02",
                    severity="critical",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="PTY spawn or dup2 (shell wiring)",
                    family="F3"
                ))
        
        return matches
    
    # F4: Obfuscated loader rules
    def _check_base64_exec(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for base64 decode followed by exec/eval."""
        matches = []
        lines = code.split('\n')
        
        has_b64 = 'base64' in code or 'b64decode' in code
        has_exec = any(x in code for x in ['exec(', 'eval(', 'compile('])
        
        if has_b64 and has_exec:
            for i, line in enumerate(lines):
                if ('base64' in line or 'b64decode' in line) and any(x in line for x in ['exec', 'eval']):
                    matches.append(RuleMatch(
                        rule_id="PC-F4-01",
                        severity="critical",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="Base64 decode feeding exec/eval",
                        family="F4"
                    ))
        
        return matches
    
    def _check_decode_exec(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for various decode operations feeding exec."""
        matches = []
        lines = code.split('\n')
        
        decode_patterns = ['zlib.decompress', 'marshal.loads', 'bytes.fromhex']
        exec_patterns = ['exec(', 'eval(', 'compile(']
        
        for decode_pat in decode_patterns:
            if decode_pat in code and any(ex in code for ex in exec_patterns):
                for i, line in enumerate(lines):
                    if decode_pat in line:
                        matches.append(RuleMatch(
                            rule_id="PC-F4-02",
                            severity="critical",
                            line=start_line + i,
                            snippet=line[:120].strip(),
                            why=f"Decoded payload ({decode_pat}) may feed exec/eval",
                            family="F4"
                        ))
                        break
        
        return matches
    
    # F5: Logic/time bomb rules
    def _check_time_based_destruction(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for time/date checks guarding destructive actions."""
        matches = []
        lines = code.split('\n')
        
        has_time_check = any(x in code for x in ['datetime', 'time.time', 'date'])
        has_destruction = any(x in code for x in ['os.remove', 'shutil.rmtree', 'unlink'])
        
        if has_time_check and has_destruction:
            for i, line in enumerate(lines):
                if any(x in line for x in ['datetime', 'time']) or any(x in line for x in ['remove', 'rmtree']):
                    matches.append(RuleMatch(
                        rule_id="PC-F5-01",
                        severity="high",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="Time-based logic bomb indicator",
                        family="F5"
                    ))
                    break
        
        return matches
    
    def _check_date_guard(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for hardcoded date comparisons."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if re.search(r'\d{4}[-/]\d{2}[-/]\d{2}', line) and any(x in line for x in ['if', '>', '<', '==']):
                matches.append(RuleMatch(
                    rule_id="PC-F5-02",
                    severity="high",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Hardcoded date comparison (time bomb)",
                    family="F5"
                ))
        
        return matches
    
    # F6: API hiding rules
    def _check_dynamic_import(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for __import__ usage."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if '__import__' in line:
                matches.append(RuleMatch(
                    rule_id="PC-F6-01",
                    severity="medium",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Dynamic import to hide API",
                    family="F6"
                ))
        
        return matches
    
    def _check_getattr_builtin(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for getattr on builtins."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'getattr' in line and ('builtin' in line.lower() or '__' in line):
                matches.append(RuleMatch(
                    rule_id="PC-F6-02",
                    severity="high",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="getattr on builtins to hide dangerous API",
                    family="F6"
                ))
        
        return matches
    
    def _check_chr_join_construction(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for chr() and join() to construct strings."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'chr(' in line and ('join' in line or '+' in line):
                matches.append(RuleMatch(
                    rule_id="PC-F6-03",
                    severity="medium",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="chr() string construction to hide API names",
                    family="F6"
                ))
        
        return matches
    
    # F7: Trojan Source rules
    def _check_bidi_characters(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for bidirectional Unicode control characters."""
        matches = []
        lines = code.split('\n')
        
        bidi_chars = ['\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                      '\u2066', '\u2067', '\u2068', '\u2069']
        
        for i, line in enumerate(lines):
            if any(char in line for char in bidi_chars):
                matches.append(RuleMatch(
                    rule_id="PC-F7-01",
                    severity="critical",
                    line=start_line + i,
                    snippet=line[:120],
                    why="Bidirectional Unicode control character (Trojan Source)",
                    family="F7"
                ))
        
        return matches
    
    def _check_zero_width_chars(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for zero-width characters."""
        matches = []
        lines = code.split('\n')
        
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        
        for i, line in enumerate(lines):
            if any(char in line for char in zero_width):
                matches.append(RuleMatch(
                    rule_id="PC-F7-02",
                    severity="high",
                    line=start_line + i,
                    snippet=line[:120],
                    why="Zero-width character (hidden code)",
                    family="F7"
                ))
        
        return matches
    
    def _check_homoglyph_identifiers(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for non-ASCII identifiers mixed with ASCII."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            # Check if line has both ASCII and non-ASCII letters
            has_ascii = any(c.isascii() and c.isalpha() for c in line)
            has_non_ascii = any(not c.isascii() and c.isalpha() for c in line)
            
            if has_ascii and has_non_ascii:
                matches.append(RuleMatch(
                    rule_id="PC-F7-03",
                    severity="medium",
                    line=start_line + i,
                    snippet=line[:120],
                    why="Mixed ASCII/non-ASCII identifiers (homoglyph)",
                    family="F7"
                ))
        
        return matches
    
    # F8: Unsafe deserialization rules
    def _check_pickle_loads(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for pickle.loads usage - only flag if loading from network/untrusted source."""
        matches = []
        lines = code.split('\n')
        
        # Check if pickle is used with network or truly untrusted data
        has_pickle = 'pickle.loads' in code or 'pickle.load' in code
        has_network_source = any(x in code for x in ['requests.', 'urlopen', 'socket.recv',
                                                      'input(', 'sys.stdin.read'])
        is_local_cache = 'cache' in code.lower() or 'CACHE' in code
        
        # Don't flag legitimate local caching
        if has_pickle and not is_local_cache:
            for i, line in enumerate(lines):
                if 'pickle.loads' in line or 'pickle.load' in line:
                    # Only flag if it's clearly from untrusted source
                    if has_network_source:
                        matches.append(RuleMatch(
                            rule_id="PC-F8-01",
                            severity="critical",
                            line=start_line + i,
                            snippet=line[:120].strip(),
                            why="Pickle deserialization of network/untrusted data",
                            family="F8"
                        ))
        
        return matches
    
    def _check_marshal_loads(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for marshal.loads usage."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'marshal.loads' in line or 'marshal.load' in line:
                matches.append(RuleMatch(
                    rule_id="PC-F8-02",
                    severity="high",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Unsafe marshal deserialization",
                    family="F8"
                ))
        
        return matches
    
    def _check_yaml_unsafe_load(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for yaml.load without safe loader."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'yaml.load' in line and 'SafeLoader' not in line and 'safe_load' not in line:
                matches.append(RuleMatch(
                    rule_id="PC-F8-03",
                    severity="high",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Unsafe yaml.load without SafeLoader",
                    family="F8"
                ))
        
        return matches
    
    # F9: Persistence rules
    def _check_crontab_modification(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for crontab modifications."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'crontab' in line and any(x in line for x in ['write', 'open', 'subprocess']):
                matches.append(RuleMatch(
                    rule_id="PC-F9-01",
                    severity="critical",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Crontab modification (persistence)",
                    family="F9"
                ))
        
        return matches
    
    def _check_bashrc_modification(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for bashrc/profile modifications."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if any(x in line for x in ['.bashrc', '.bash_profile', '.profile']) and \
               any(x in line for x in ['write', 'open', 'append']):
                matches.append(RuleMatch(
                    rule_id="PC-F9-02",
                    severity="critical",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="Shell profile modification (persistence)",
                    family="F9"
                ))
        
        return matches
    
    def _check_authorized_keys(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for authorized_keys modifications."""
        matches = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if 'authorized_keys' in line and any(x in line for x in ['write', 'open', 'append']):
                matches.append(RuleMatch(
                    rule_id="PC-F9-03",
                    severity="critical",
                    line=start_line + i,
                    snippet=line[:120].strip(),
                    why="SSH authorized_keys modification (persistence)",
                    family="F9"
                ))
        
        return matches
    
    # F10: Download and execute rules
    def _check_download_exec(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for download followed by execute pattern."""
        matches = []
        
        has_download = any(x in code for x in ['requests.get', 'urlopen', 'urllib'])
        has_exec = any(x in code for x in ['subprocess', 'os.system', 'exec('])
        
        if has_download and has_exec:
            lines = code.split('\n')
            for i, line in enumerate(lines):
                if any(x in line for x in ['requests.get', 'urlopen', 'urllib']):
                    matches.append(RuleMatch(
                        rule_id="PC-F10-01",
                        severity="critical",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="Download and execute pattern",
                        family="F10"
                    ))
                    break
        
        return matches
    
    def _check_chmod_exec(self, code: str, start_line: int) -> List[RuleMatch]:
        """Check for chmod followed by execute."""
        matches = []
        lines = code.split('\n')
        
        has_chmod = 'chmod' in code
        has_exec = any(x in code for x in ['subprocess', 'os.system', 'exec'])
        
        if has_chmod and has_exec:
            for i, line in enumerate(lines):
                if 'chmod' in line:
                    matches.append(RuleMatch(
                        rule_id="PC-F10-02",
                        severity="high",
                        line=start_line + i,
                        snippet=line[:120].strip(),
                        why="chmod before execute (download-exec pattern)",
                        family="F10"
                    ))
        
        return matches
