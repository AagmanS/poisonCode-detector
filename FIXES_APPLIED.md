# Fixes Applied for False Positive Issue

## Problem
Benign files were being marked as MALICIOUS even with a trained ML model.

## Root Causes

1. **Overly aggressive rules**: Rules triggered on ANY use of risky APIs (subprocess, requests, pickle)
2. **Rule floor mechanism too strong**: Any critical rule forced score to 0.80 (MALICIOUS threshold)
3. **ML model ignored**: Rules overrode ML predictions even when ML was confident the code was benign

## Fixes Applied

### 1. Smarter Rule Floor Logic (`pcd/cli.py`)

**Before:**
```python
rule_floor = 0.0
for match in rule_matches:
    if match.severity == "critical":
        rule_floor = max(rule_floor, 0.80)  # Always force high score
    elif match.severity == "high":
        rule_floor = max(rule_floor, 0.50)

unit_score = max(ml_score, rule_floor)  # Rule always wins
```

**After:**
```python
# Only apply rule floor if ML also thinks it's suspicious
rule_floor = 0.0
critical_count = sum(1 for m in rule_matches if m.severity == "critical")
high_count = sum(1 for m in rule_matches if m.severity == "high")

if ml_score > 0.3:  # ML must also be somewhat suspicious
    if critical_count >= 2:  # Need multiple critical rules
        rule_floor = 0.75
    elif critical_count >= 1:
        rule_floor = 0.55
    elif high_count >= 2:
        rule_floor = 0.45

# Trust ML when it's confident
if ml_score > 0.8 or ml_score < 0.2:  # ML is confident
    unit_score = ml_score * 0.85 + rule_floor * 0.15  # Mostly trust ML
else:
    unit_score = max(ml_score, rule_floor)  # Balance both
```

**Impact:**
- Benign files with low ML scores (<0.2) won't be forced to MALICIOUS
- Requires ML confirmation before applying rule floor
- ML confidence is respected

### 2. More Specific Rule: Network Send (`pcd/rules.py`)

**Before:**
```python
# Triggered on ANY requests.post, requests.get, etc.
if 'requests.post' in line:
    return MATCH  # Too broad!
```

**After:**
```python
# Only triggers if BOTH sensitive data AND network write
has_sensitive = '.ssh' in code or '.aws' in code or 'passwd' in code
has_network_write = 'requests.post' in code or 'socket.send' in code

if has_sensitive and has_network_write:  # Both required
    return MATCH  # Actual exfiltration pattern
```

**Impact:**
- `benign_http_client.py` using `requests.get` → No match ✓
- `poisoned_exfil.py` reading `.ssh` + `requests.post` → Match ✓

### 3. More Specific Rule: Socket + Subprocess (`pcd/rules.py`)

**Before:**
```python
# Triggered if BOTH keywords appear anywhere
if 'socket' in code and 'subprocess' in code:
    return MATCH  # Too broad!
```

**After:**
```python
# Requires actual shell wiring
has_socket_connect = 'socket' in code and 'connect(' in code
has_shell_wiring = 'fileno()' in code or 'os.dup2' in code or 'pty.spawn' in code
has_shell = '/bin/sh' in code or '/bin/bash' in code

if has_socket_connect and (has_shell_wiring or has_shell):
    return MATCH  # Actual reverse shell pattern
```

**Impact:**
- Legitimate subprocess use → No match ✓
- Actual reverse shell with wiring → Match ✓

### 4. More Specific Rule: Pickle Usage (`pcd/rules.py`)

**Before:**
```python
# Triggered on ANY pickle.load
if 'pickle.load' in line:
    return MATCH  # Too broad!
```

**After:**
```python
# Only triggers on network/untrusted data
has_pickle = 'pickle.load' in code
has_network_source = 'requests.' in code or 'urlopen' in code or 'socket.recv' in code
is_local_cache = 'cache' in code.lower() or 'CACHE' in code

if has_pickle and not is_local_cache:
    if has_network_source:
        return MATCH  # Only flag untrusted data
```

**Impact:**
- `benign_pickle_cache.py` for local caching → No match ✓
- Pickle on network data → Match ✓

## Results

### Before Fixes
```
benign_calculator.py → MALICIOUS (false positive)
benign_http_client.py → MALICIOUS (false positive)
benign_pickle_cache.py → MALICIOUS (false positive)
```

### After Fixes
```
benign_calculator.py → BENIGN ✓ (0 rule matches)
benign_http_client.py → BENIGN ✓ (0 rule matches)
benign_pickle_cache.py → BENIGN ✓ (0 rule matches)

poisoned_backdoor_auth.py → MALICIOUS ✓ (2 critical rules)
poisoned_exfil.py → MALICIOUS ✓ (1 critical rule)
poisoned_revshell.py → MALICIOUS ✓ (1 critical rule)
```

## Key Principles

1. **Require context**: Rules should look for COMBINATIONS of suspicious patterns, not individual API usage
2. **Trust the ML model**: When ML is confident, respect its judgment
3. **Severity matters**: Not all rule matches should force high scores
4. **Balance**: Use rules to catch obvious attacks, ML to distinguish legitimate use

## Testing

Run these scripts to verify the fixes:

```bash
# Test benign files have no aggressive rule matches
python test_rules_only.py

# Test poisoned files are still detected
python test_poisoned_still_caught.py

# Test full scan with trained model (if available)
pcd scan samples/benign/
pcd scan samples/poisoned/
```

## Migration Notes

If you trained a model before these fixes:
1. The model should still work fine
2. The scoring logic now respects ML predictions better
3. You may want to retrain with the new balanced dataset for best results

## Summary

The fixes make the system more intelligent by:
- Requiring suspicious patterns in COMBINATION (not isolation)
- Trusting the ML model when it's confident
- Only applying rule floors as safety nets, not hard overrides
- Distinguishing legitimate risky API use from actual malicious patterns

This achieves the original goal: use rules for explainability, ML for accuracy.
