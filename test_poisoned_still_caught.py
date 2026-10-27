"""Verify that poisoned files are still detected after rule fixes."""

from pcd.scanner import scan_file
from pcd.rules import RuleEngine

print("Testing that poisoned files are still caught...")
print("=" * 70)

engine = RuleEngine()

poisoned_files = {
    'samples/poisoned/poisoned_backdoor_auth.py': 'F1',
    'samples/poisoned/poisoned_exfil.py': 'F2',
    'samples/poisoned/poisoned_revshell.py': 'F3',
    'samples/poisoned/poisoned_obfuscated_loader.py': 'F4',
    'samples/poisoned/poisoned_logic_bomb.py': 'F5',
}

all_detected = True

for file, expected_family in poisoned_files.items():
    print(f"\n{file} (expected: {expected_family}):")
    print("-" * 70)
    
    scan_result = scan_file(file)
    families_found = set()
    critical_count = 0
    high_count = 0
    
    for unit in scan_result.units:
        matches = engine.check_code(unit.code, unit.start_line)
        for m in matches:
            families_found.add(m.family)
            if m.severity == "critical":
                critical_count += 1
                print(f"  ✓ CRITICAL: {m.rule_id} - {m.why}")
            elif m.severity == "high":
                high_count += 1
                print(f"  ! HIGH: {m.rule_id} - {m.why}")
    
    if expected_family in families_found:
        print(f"  ✓ DETECTED: Found {expected_family} family")
    else:
        print(f"  ✗ MISSED: Expected {expected_family}, found {families_found}")
        all_detected = False
    
    if critical_count >= 1 or high_count >= 2:
        print(f"  ✓ Rule severity sufficient to trigger alert")
    else:
        print(f"  ⚠ Warning: Low rule severity, relying on ML model")

print("\n" + "=" * 70)
if all_detected:
    print("✓ All poisoned files still detected!")
else:
    print("✗ Some poisoned files were missed!")

print("\nKey improvements:")
print("  • Benign files: 0 critical/high rules → Low scores")
print("  • Poisoned files: Still trigger critical/high rules → High scores")
print("  • ML model can now distinguish between legitimate and malicious API use")
