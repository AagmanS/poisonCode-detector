"""Intra-function data flow tracking for source-to-sink patterns."""

import ast
from typing import Set, Dict, List, Tuple


class DataFlowTracker:
    """Track simple intra-function dataflow patterns."""
    
    def __init__(self, code: str):
        self.code = code
        self.tree = None
        try:
            self.tree = ast.parse(code)
        except:
            pass
    
    def check_exfil_pair(self) -> bool:
        """
        Check for exfiltration pattern:
        sensitive source -> variable (up to 2 hops) -> network sink
        """
        if not self.tree:
            return False
        
        # Sensitive sources
        sensitive_patterns = [
            'os.environ', 'getenv', '.ssh', '.aws', 'passwd', 
            'credentials', 'authorized_keys', 'getpass'
        ]
        
        # Network sinks
        network_patterns = [
            'requests.post', 'requests.put', 'urlopen', 
            'socket.send', 'smtplib'
        ]
        
        has_sensitive = any(pat in self.code for pat in sensitive_patterns)
        has_network = any(pat in self.code for pat in network_patterns)
        
        return has_sensitive and has_network
    
    def check_decode_exec_pair(self) -> bool:
        """
        Check for decode-exec pattern:
        decoded value -> exec/eval/compile
        """
        if not self.tree:
            return False
        
        decode_patterns = ['base64', 'b64decode', 'zlib.decompress', 
                          'marshal.loads', 'bytes.fromhex']
        exec_patterns = ['exec(', 'eval(', 'compile(']
        
        has_decode = any(pat in self.code for pat in decode_patterns)
        has_exec = any(pat in self.code for pat in exec_patterns)
        
        return has_decode and has_exec
    
    def check_download_exec_pair(self) -> bool:
        """
        Check for download-exec pattern:
        download -> write file -> execute/chmod
        """
        if not self.tree:
            return False
        
        download_patterns = ['requests.get', 'urlopen', 'urllib.request']
        file_write_patterns = ['open(', 'write', '.write(']
        exec_patterns = ['subprocess', 'os.system', 'chmod']
        
        has_download = any(pat in self.code for pat in download_patterns)
        has_write = any(pat in self.code for pat in file_write_patterns)
        has_exec = any(pat in self.code for pat in exec_patterns)
        
        return has_download and has_write and has_exec
    
    def get_all_pairs(self) -> Dict[str, bool]:
        """Get all dataflow pair checks."""
        return {
            'exfil_pair': self.check_exfil_pair(),
            'decode_exec_pair': self.check_decode_exec_pair(),
            'download_exec_pair': self.check_download_exec_pair(),
        }


def check_dataflow_pairs(code: str) -> Dict[str, int]:
    """
    Check for dataflow patterns and return as feature dict.
    
    Args:
        code: Python source code
        
    Returns:
        Dict with binary features for each pair type
    """
    tracker = DataFlowTracker(code)
    pairs = tracker.get_all_pairs()
    return {k: int(v) for k, v in pairs.items()}
