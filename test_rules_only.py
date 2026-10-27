"""Test that rules are now less aggressive on benign files."""

from pcd.scanner import scan_file
from pcd.rules import RuleEngine

print("Testing rule engine on benign files...")
print("=" * 70)

engine = RuleEngine()

benign_files = [
    'samples/benign/benign_calculator.py',
    'samples/benign/benign_http_client.py',
    'samples/benign/benign_pickle_cache.py'
]

for file in benign_files:
    print(f"\n{file}:")
    print("-" * 70)
    
    scan_result = scan_file(file)
    total_critical = 0
    total_high = 0
    total_matches = 0
    
    for unit in scan_result.units:
        matches = engine.check_code(unit.code, unit.start_line)
        if matches:
            critical = [m for m in matches if m.severity == "critical"]
            high = [m for m in matches if m.severity == "high"]
            low = [m for m in matches if m.severity in ["low", "medium"]]
            
            total_critical += len(critical)
            total_high += len(high)
            total_matches += len(matches)
            
            print(f"  Unit '{unit.name}': {len(matches)} matches")
            
            if critical:
                print(f"    ✗ CRITICAL rules:")
                for m in critical:
                    print(f"      - {m.rule_id}: {m.why}")
            
            if high:
                print(f"    ! HIGH rules:")
                for m in high:
                    print(f"      - {m.rule_id}: {m.why}")
            
            if low:
                print(f"    ~ Low/Medium rules:")
                for m in low:
                    print(f"      - {m.rule_id}: {m.why}")
    
    print(f"\n  Summary: {total_matches} total ({total_critical} critical, {total_high} high)")
    
    # Evaluate
    if total_critical >= 2:
        print("  ⚠ PROBLEM: Multiple critical rules - would force MALICIOUS verdict")
    elif total_critical >= 1:
        print("  ⚠ CAUTION: 1 critical rule - would push toward MALICIOUS if ML uncertain")
    elif total_high >= 2:
        print("  ~ ACCEPTABLE: Multiple high rules - ML model should handle this")
    elif total_matches == 0:
        print("  ✓ PERFECT: No rule matches - clearly benign")
    else:
        print("  ✓ GOOD: Low severity only - ML model will handle")

print("\n" + "=" * 70)
print("Rule fixes summary:")
print("  • Network send now requires BOTH sensitive data AND network write")
print("  • Socket subprocess now requires actual shell wiring")
print("  • Pickle now distinguishes local caching from untrusted data")
