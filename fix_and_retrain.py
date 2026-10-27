"""Fix the model compatibility issue by retraining with current environment."""

import sys
import os
from pathlib import Path

print("PoisonCode Detector - Model Compatibility Fix")
print("=" * 70)

# Check Python version
print(f"\nPython version: {sys.version}")

# Check scikit-learn
try:
    import sklearn
    print(f"scikit-learn version: {sklearn.__version__}")
except:
    print("ERROR: scikit-learn not installed!")
    sys.exit(1)

# Delete old incompatible model
model_path = Path('models/pcd_model.joblib')
if model_path.exists():
    print(f"\nDeleting old model: {model_path}")
    model_path.unlink()
    
card_path = Path('models/model_card.json')
if card_path.exists():
    card_path.unlink()

# Retrain
print("\nRetraining model with current scikit-learn version...")
print("This will take a few minutes...")

import subprocess
result = subprocess.run([
    sys.executable, '-m', 'pcd.cli', 'train',
    '--data', 'data/processed',
    '--out', 'models/',
    '--seed', '42'
], capture_output=True, text=True)

print(result.stdout)
if result.returncode != 0:
    print("ERROR during training:")
    print(result.stderr)
    sys.exit(1)

print("\n" + "=" * 70)
print("✓ Model retrained successfully!")
print("\nNow test with:")
print("  pcd scan samples/benign/")
print("  pcd scan samples/poisoned/")
