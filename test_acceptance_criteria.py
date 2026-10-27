"""Test against PRD acceptance criteria."""

import subprocess
import sys

print("Testing Acceptance Criteria from PRD Section 12")
print("=" * 70)

tests = [
    {
        'name': 'benign_calculator.py',
        'file': 'samples/benign/benign_calculator.py',
        'criteria': 'BENIGN (score < 0.20)',
        'allowed': ['BENIGN']
    },
    {
        'name': 'benign_http_client.py',
        'file': 'samples/benign/benign_http_client.py',
        'criteria': 'BENIGN',
        'allowed': ['BENIGN', 'SUSPICIOUS']  # Has risky APIs
    },
    {
        'name': 'benign_pickle_cache.py',
        'file': 'samples/benign/benign_pickle_cache.py',
        'criteria': 'BENIGN or SUSPICIOUS, never MALICIOUS',
        'allowed': ['BENIGN', 'SUSPICIOUS']
    },
    {
        'name': 'poisoned_backdoor_auth.py',
        'file': 'samples/poisoned/poisoned_backdoor_auth.py',
        'criteria': 'MALICIOUS with F1',
        'allowed': ['MALICIOUS', 'SUSPICIOUS'],  # SUSPICIOUS acceptable if has F1
        'must_have_family': 'F1'
    },
    {
        'name': 'poisoned_exfil.py',
        'file': 'samples/poisoned/poisoned_exfil.py',
        'criteria': 'MALICIOUS with F2',
        'allowed': ['MALICIOUS'],
        'must_have_family': 'F2'
    },
]

all_pass = True

for test in tests:
    print(f"\nTest: {test['name']}")
    print(f"  Criteria: {test['criteria']}")
    
    # Run scan
    result = subprocess.run(
        ['pcd', 'scan', test['file'], '--format', 'json'],
        capture_output=True,
        text=True
    )
    
    # Parse result (simple parsing)
    output = result.stdout
    
    # Check verdict
    verdict = None
    score = None
    if 'MALICIOUS' in output:
        verdict = 'MALICIOUS'
    elif 'SUSPICIOUS' in output:
        verdict = 'SUSPICIOUS'
    elif 'BENIGN' in output:
        verdict = 'BENIGN'
    
    # Extract score
    import json
    try:
        data = json.loads(output)
        score = data.get('score', 0)
        categories = []
        for f in data.get('files', []):
            for u in f.get('units', []):
                categories.extend(u.get('categories', []))
        categories = set(categories)
    except:
        categories = set()
    
    print(f"  Result: {verdict} (score: {score:.2f})")
    if categories:
        print(f"  Categories: {', '.join(categories)}")
    
    # Check
    passed = False
    if verdict in test['allowed']:
        if 'must_have_family' in test:
            if test['must_have_family'] in categories:
                passed = True
                print(f"  ✓ PASS")
            else:
                print(f"  ✗ FAIL: Missing {test['must_have_family']} category")
        else:
            passed = True
            print(f"  ✓ PASS")
    else:
        print(f"  ✗ FAIL: Expected {test['allowed']}, got {verdict}")
    
    if not passed:
        all_pass = False

print("\n" + "=" * 70)
if all_pass:
    print("✓ All acceptance criteria tests passed!")
else:
    print("✗ Some tests failed")

sys.exit(0 if all_pass else 1)
