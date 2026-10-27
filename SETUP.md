# Setup Guide

## Prerequisites

- Python 3.10 or higher
- pip package manager

## Installation Steps

### 1. Create a Virtual Environment (Recommended)

```powershell
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Or on Unix/Mac
python3 -m venv venv
source venv/bin/activate
```

### 2. Install the Package

```powershell
# Install in development mode with dependencies
pip install -e .

# Or install with development dependencies (for testing)
pip install -e ".[dev]"
```

### 3. Verify Installation

```powershell
pcd --version
```

You should see: `pcd 0.1.0`

## First-Time Workflow

### Step 1: Generate Dataset

```powershell
pcd generate-data --out data/processed --n-benign 3000 --n-malicious 3000 --seed 42
```

This will:
- Collect benign samples from Python standard library
- Generate synthetic malicious samples for all 10 attack families
- Create `data/processed/dataset.csv`
- Takes ~2-5 minutes depending on your system

### Step 2: Train the Model

```powershell
pcd train --data data/processed --out models/
```

This will:
- Train the feature-based model (gradient boosting)
- Train the token-based model (logistic regression)
- Calibrate the ensemble
- Tune thresholds on validation set
- Save `models/pcd_model.joblib` and `models/model_card.json`
- Takes ~5-10 minutes depending on your system

### Step 3: Evaluate the Model

```powershell
pcd eval --data data/processed --model models/pcd_model.joblib
```

This will:
- Evaluate on test set
- Generate metrics, confusion matrix, ROC curve
- Run leave-one-family-out (LOFO) evaluation
- Save results to `reports/`
- Takes ~10-20 minutes (LOFO is comprehensive)

### Step 4: Test on Samples

```powershell
# Scan benign samples (should all be BENIGN)
pcd scan samples/benign/

# Scan poisoned samples (should be MALICIOUS)
pcd scan samples/poisoned/

# Test the build gate
pcd build --target samples/poisoned -- echo BUILD_RAN
# Should exit with code 2 and NOT print BUILD_RAN

pcd build --target samples/benign -- echo BUILD_RAN
# Should print BUILD_RAN and exit 0
```

## Quick Demo

Once setup is complete, you can demo the tool:

```powershell
# Create a test file
@"
def authenticate(user, password):
    if user == 'admin_backdoor':
        return True
    return False
"@ | Out-File -Encoding utf8 test_backdoor.py

# Scan it
pcd scan test_backdoor.py

# You should see a MALICIOUS or SUSPICIOUS verdict with F1 category
```

## Troubleshooting

### Import Errors

If you get import errors:

```powershell
# Make sure you're in the project root directory
cd c:\cdP

# Reinstall in development mode
pip install -e .
```

### Model Not Found

If you get "Model not found" errors:

```powershell
# Check if model exists
dir models\pcd_model.joblib

# If not, train it first
pcd train --data data/processed --out models/
```

### Dataset Not Found

```powershell
# Generate dataset first
pcd generate-data --out data/processed --seed 42
```

### Slow Performance

- First model load can be slow (~1-2 seconds)
- Subsequent scans are faster
- LOFO evaluation is intentionally comprehensive and takes time

### Memory Issues

If you run out of memory during training:

```powershell
# Reduce dataset size
pcd generate-data --out data/processed --n-benign 1000 --n-malicious 1000 --seed 42
```

## Running Tests

```powershell
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_no_execution.py -v

# Run with coverage
pytest tests/ --cov=pcd --cov-report=html
```

## Configuration

Create a `pcd.yaml` in your project directory:

```yaml
suspicious_threshold: 0.40
malicious_threshold: 0.70
fail_on: malicious
model_path: models/pcd_model.joblib
ignore_globs:
  - "**/.git/**"
  - "**/venv/**"
```

## Next Steps

- Integrate `pcd build` into your CI/CD pipeline
- Add a pre-commit hook
- Experiment with different thresholds
- Try scanning your own Python projects

## Getting Help

- Check the README.md for detailed command documentation
- Run `pcd COMMAND --help` for command-specific help
- Review sample files in `samples/` directory
