"""Test that benign files are correctly identified after fixes."""

import sys
from pathlib import Path

print("Testing benign file classification...")
print("=" * 70)

# Check if model exists
model_path = Path('models/pcd_model.joblib')
if not model_path.exists():
    print("ERROR: Model not found. Please run:")
    print("  pcd train --data data/processed --out models/")
    sys.exit(1)

from pcd.model import PCDModel
from pcd.scanner import scan_file
from pcd.rules import RuleEngine

model = PCDModel.load(str(model_path))
engine = RuleEngine()

benign_files = [
    'samples/benign/benign_calculator.py',
    'samples/benign/benign_http_client.py',
    'samples/benign/benign_pickle_cache.py'
]

print(f"\nModel thresholds:")
print(f"  Suspicious: {model.suspicious_threshold:.2f}")
print(f"  Malicious: {model.malicious_threshold:.2f}")
print()

all_pass = True

for file in benign_files:
    print(f"\nTesting: {file}")
    print("-" * 70)
    
    scan_result = scan_file(file)
    max_score = 0.0
    max_verdict = "BENIGN"
    
    for unit in scan_result.units:
        # Get ML prediction
        ml_score, ml_verdict = model.predict(unit.code)
        
        # Get rule matches
        rule_matches = engine.check_code(unit.code, unit.start_line)
        
        # Calculate final score (using same logic as CLI)
        rule_floor = 0.0
        critical_count = sum(1 for m in rule_matches if m.severity == "critical")
        high_count = sum(1 for m in rule_matches if m.severity == "high")
        
        if ml_score > 0.3:
            if critical_count >= 2:
                rule_floor = max(rule_floor, 0.75)
            elif critical_count >= 1:
                rule_floor = max(rule_floor, 0.55)
            elif high_count >= 2:
                rule_floor = max(rule_floor, 0.45)
        
        if ml_score > 0.8 or ml_score < 0.2:
            unit_score = ml_score * 0.85 + rule_floor * 0.15
        else:
            unit_score = max(ml_score, rule_floor)
        
        if unit_score >= model.malicious_threshold:
            unit_verdict = "MALICIOUS"
        elif unit_score >= model.suspicious_threshold:
            unit_verdict = "SUSPICIOUS"
        else:
            unit_verdict = "BENIGN"
        
        max_score = max(max_score, unit_score)
        if unit_verdict != "BENIGN":
            max_verdict = unit_verdict
        
        print(f"  Unit '{unit.name}':")
        print(f"    ML score: {ml_score:.3f}")
        print(f"    Rules: {len(rule_matches)} matches ({critical_count} critical, {high_count} high)")
        print(f"    Rule floor: {rule_floor:.3f}")
        print(f"    Final score: {unit_score:.3f}")
        print(f"    Verdict: {unit_verdict}")
    
    print(f"\n  File verdict: {max_verdict} (score: {max_score:.3f})")
    
    # Check result
    if max_verdict == "MALICIOUS":
        print("  ✗ FAIL - Should be BENIGN or SUSPICIOUS, not MALICIOUS")
        all_pass = False
    elif max_verdict == "BENIGN":
        print("  ✓ PASS - Correctly identified as BENIGN")
    else:
        print("  ~ ACCEPTABLE - SUSPICIOUS is okay for hard negatives")

print("\n" + "=" * 70)
if all_pass:
    print("✓ All benign files correctly classified!")
else:
    print("✗ Some benign files were incorrectly marked as MALICIOUS")
    print("\nThis usually means:")
    print("  1. Model needs more training data")
    print("  2. Rules are still too aggressive")
    print("  3. Thresholds need adjustment")

sys.exit(0 if all_pass else 1)
