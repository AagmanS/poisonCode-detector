# PoisonCode Detector

A command-line tool that detects semantically malicious patterns (backdoors, data exfiltration, reverse shells, obfuscated loaders, logic bombs, hidden Unicode tricks) in Python source code and acts as a gate in the compile/build step.

**Version**: 0.1.0 (base working prototype)

## Overview

PoisonCode Detector (`pcd`) combines:
- **Rule engine**: Finds and explains suspicious patterns with line numbers and categories
- **ML ensemble**: Gradient boosting on semantic features + logistic regression on token n-grams
- **Build gate**: Blocks compilation if malicious code is detected

## Attack Families Detected

1. **F1**: Backdoor authentication (hardcoded credentials)
2. **F2**: Data exfiltration (sensitive files → network)
3. **F3**: Reverse shell (socket + shell wiring)
4. **F4**: Obfuscated payload loader (base64/zlib → exec)
5. **F5**: Logic/time bomb (date-guarded destruction)
6. **F6**: API hiding (dynamic import, getattr tricks)
7. **F7**: Trojan Source (bidi/zero-width/homoglyph Unicode)
8. **F8**: Unsafe deserialization (pickle/marshal/yaml.load)
9. **F9**: Persistence (crontab, .bashrc, authorized_keys)
10. **F10**: Download-and-execute

## Installation

```bash
# Install dependencies
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```bash
# 1. Generate training data
pcd generate-data --out data/processed --n-benign 3000 --n-malicious 3000 --seed 42

# 2. Train the model
pcd train --data data/processed --out models/

# 3. Evaluate the model
pcd eval --data data/processed --model models/pcd_model.joblib

# 4. Scan a file or directory
pcd scan samples/

# 5. Gate a build
pcd build --target samples/poisoned -- echo BUILD_RAN
```

## Commands

### `pcd scan`

Scan Python files and output verdicts with evidence.

```bash
# Scan a file
pcd scan myfile.py

# Scan a directory
pcd scan src/

# JSON output
pcd scan src/ --format json --out report.json

# Use custom model
pcd scan src/ --model path/to/model.joblib
```

**Exit codes**: 0 (benign), 1 (suspicious), 2 (malicious), 3 (error)

### `pcd build`

Scan before build and block if malicious code is found.

```bash
# Block on malicious only (default)
pcd build --target ./src -- python -m compileall ./src

# Block on suspicious or malicious
pcd build --target ./src --fail-on suspicious -- make compile
```

**Exit codes**: 0 (clean build), 1 (suspicious found), 2 (malicious, build blocked), 3 (error)

### `pcd compile`

Scan a Python file then compile it with `py_compile`.

```bash
pcd compile myfile.py
```

### `pcd generate-data`

Generate synthetic training dataset.

```bash
pcd generate-data --out data/processed --n-benign 3000 --n-malicious 3000 --seed 42
```

Produces `data/processed/dataset.csv` with:
- Benign samples from standard library + hard negatives (legit risky API usage)
- Malicious samples (10 families × ~300 per family)
- Splits: 70/15/15 train/val/test, grouped by host file

**⚠️ WARNING**: Dataset contains inert synthetic malware. Never execute samples.

### `pcd train`

Train the ensemble model.

```bash
pcd train --data data/processed --out models/
```

Trains:
- HistGradientBoostingClassifier on ~60 semantic features
- LogisticRegression on TF-IDF token n-grams
- Ensemble: 0.6 × feature_model + 0.4 × token_model, calibrated
- Tunes thresholds on validation set

### `pcd eval`

Evaluate model and generate reports.

```bash
pcd eval --data data/processed --model models/pcd_model.joblib --out reports/
```

Outputs:
- `reports/metrics.json`: precision, recall, F1, ROC-AUC, FPR
- `reports/confusion_matrix.png`
- `reports/roc_curve.png`
- `reports/lofo_results.json`: leave-one-family-out results

## Configuration

Create `pcd.yaml` in your project:

```yaml
suspicious_threshold: 0.40
malicious_threshold: 0.70
fail_on: malicious  # or 'suspicious'
model_path: models/pcd_model.joblib
ignore_globs:
  - "**/.git/**"
  - "**/venv/**"
  - "**/node_modules/**"
  - "**/__pycache__/**"
```

## Sample Files

The `samples/` directory contains test files:

**Benign**:
- `benign_calculator.py`: Simple calculator
- `benign_http_client.py`: Legitimate requests + subprocess use
- `benign_pickle_cache.py`: Legitimate pickle for local cache

**Poisoned** (inert, safe for scanning):
- `poisoned_backdoor_auth.py`: F1 backdoor
- `poisoned_exfil.py`: F2 exfiltration
- `poisoned_revshell.py`: F3 reverse shell
- `poisoned_obfuscated_loader.py`: F4+F6 obfuscated loader
- `poisoned_logic_bomb.py`: F5 time bomb
- `poisoned_trojan_source.py`: F7 Unicode attack
- `poisoned_downloader.py`: F10 download-exec

## Testing

```bash
# Run tests
pytest tests/

# Test that code is never executed
pytest tests/test_no_execution.py -v
```

## Architecture

```
pcd/
├── cli.py          # Command-line interface
├── scanner.py      # File discovery and unit splitting
├── parsing.py      # Safe AST parsing (never executes code)
├── rules.py        # Rule engine (25+ detection rules)
├── features.py     # Feature extraction (~60 features)
├── dataflow.py     # Source-to-sink tracking
├── model.py        # ML training and inference
├── report.py       # Console and JSON output
└── gate.py         # Build gate logic
```

## Metrics (Prototype Targets)

| Metric | Target | Note |
|--------|--------|------|
| Malicious recall | ≥ 0.90 | On test split |
| Malicious precision | ≥ 0.90 | On test split |
| ROC-AUC | ≥ 0.95 | On test split |
| FPR (all benign) | ≤ 3% | False positive rate |
| FPR (hard negatives) | ≤ 8% | Benign code using risky APIs |
| LOFO mean recall | ≥ 0.70 | Unseen attack family |
| Latency | < 1s | Per 500-line file |

## Limitations and Honest Reporting

### What This Prototype Does

✅ Detects the 10 attack families in clean synthetic samples  
✅ Distinguishes malicious from legitimate risky-API usage  
✅ Provides line-level evidence and explanations  
✅ Blocks builds before malicious code compiles  
✅ Generalizes to unseen attack families (LOFO)

### What This Prototype Does NOT Do

❌ **Real-world malware datasets**: Trained on synthetic data. Real malware may evade.  
❌ **Adversarial robustness**: A determined attacker who knows the model can evade it.  
❌ **Multi-language support**: Python only (v0).  
❌ **Vulnerability detection**: Targets deliberate malice, not accidental bugs.  
❌ **Deep learning**: Uses classical ML. Transformers are future work.  
❌ **Perfect accuracy**: Synthetic test scores are optimistic. Trust LOFO and samples.

### Known Risks

- **Template memorization**: Model may memorize synthetic patterns. Mitigated by:
  - Injecting payloads into real benign hosts
  - Grouping splits by host_id
  - LOFO evaluation
  - Hard negatives

- **False positives on legitimate code**: Mitigated by:
  - 25% hard negatives in training data
  - Separate FPR metric for hard negatives
  - Rule floor (high-severity rules → suspicious, not always malicious)

- **Evasion**: Documented limitation. F6 (API hiding) and obfuscation features raise suspicion on opaque code, but determined evasion is possible.

## Development

```bash
# Run tests
pytest tests/ -v

# Check that scanner never executes code
pytest tests/test_no_execution.py

# Generate dataset
pcd generate-data --out data/processed --seed 42

# Train and evaluate
pcd train --data data/processed --out models/
pcd eval --data data/processed --model models/pcd_model.joblib
```

## Safety

- **Scanner never executes scanned code**: Uses `ast.parse` only, never `import`, `exec`, or `eval`
- **Dataset payloads are inert**: Use `example.invalid`, `127.0.0.1`, no real credentials
- **Test suite verifies non-execution**: See `tests/test_no_execution.py`

## License

This is a prototype for research and educational purposes.

## Citation

If you use this tool in research, please cite:

```
PoisonCode Detector v0.1.0 (2026)
A hybrid rule-ML tool for detecting malicious code patterns in Python
```

---

**Built with**: Python 3.10+, scikit-learn, pandas, numpy, joblib, PyYAML, matplotlib, pytest
