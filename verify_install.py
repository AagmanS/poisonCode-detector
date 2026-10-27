"""Verification script to check if PoisonCode Detector is correctly installed."""

import sys
from pathlib import Path


def check_imports():
    """Check if all required modules can be imported."""
    print("Checking imports...")
    
    required_modules = [
        'pcd',
        'pcd.parsing',
        'pcd.scanner',
        'pcd.rules',
        'pcd.features',
        'pcd.dataflow',
        'pcd.model',
        'pcd.report',
        'pcd.gate',
        'pcd.cli',
    ]
    
    failed = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✓ {module}")
        except ImportError as e:
            print(f"  ✗ {module}: {e}")
            failed.append(module)
    
    return len(failed) == 0


def check_dependencies():
    """Check if all required dependencies are installed."""
    print("\nChecking dependencies...")
    
    required_deps = [
        'sklearn',
        'pandas',
        'numpy',
        'joblib',
        'yaml',
        'matplotlib',
    ]
    
    failed = []
    for dep in required_deps:
        try:
            __import__(dep)
            print(f"  ✓ {dep}")
        except ImportError as e:
            print(f"  ✗ {dep}: {e}")
            failed.append(dep)
    
    return len(failed) == 0


def check_file_structure():
    """Check if required directories and files exist."""
    print("\nChecking file structure...")
    
    required_paths = [
        'pcd/',
        'data/',
        'samples/benign/',
        'samples/poisoned/',
        'tests/',
        'pyproject.toml',
        'pcd.yaml',
        'README.md',
    ]
    
    root = Path(__file__).parent
    failed = []
    
    for path_str in required_paths:
        path = root / path_str
        if path.exists():
            print(f"  ✓ {path_str}")
        else:
            print(f"  ✗ {path_str} (not found)")
            failed.append(path_str)
    
    return len(failed) == 0


def check_cli():
    """Check if CLI is accessible."""
    print("\nChecking CLI...")
    
    try:
        from pcd import cli
        print("  ✓ CLI module imported successfully")
        
        # Check if main function exists
        if hasattr(cli, 'main'):
            print("  ✓ main() function found")
        else:
            print("  ✗ main() function not found")
            return False
        
        return True
    except ImportError as e:
        print(f"  ✗ Failed to import CLI: {e}")
        return False


def check_samples():
    """Check if sample files exist."""
    print("\nChecking sample files...")
    
    root = Path(__file__).parent
    
    benign_samples = [
        'samples/benign/benign_calculator.py',
        'samples/benign/benign_http_client.py',
        'samples/benign/benign_pickle_cache.py',
    ]
    
    poisoned_samples = [
        'samples/poisoned/poisoned_backdoor_auth.py',
        'samples/poisoned/poisoned_exfil.py',
        'samples/poisoned/poisoned_revshell.py',
        'samples/poisoned/poisoned_obfuscated_loader.py',
        'samples/poisoned/poisoned_logic_bomb.py',
        'samples/poisoned/poisoned_trojan_source.py',
        'samples/poisoned/poisoned_downloader.py',
    ]
    
    all_samples = benign_samples + poisoned_samples
    failed = []
    
    for sample in all_samples:
        path = root / sample
        if path.exists():
            print(f"  ✓ {sample}")
        else:
            print(f"  ✗ {sample} (not found)")
            failed.append(sample)
    
    return len(failed) == 0


def main():
    """Run all verification checks."""
    print("=" * 70)
    print("PoisonCode Detector Installation Verification")
    print("=" * 70)
    
    checks = [
        ("Imports", check_imports),
        ("Dependencies", check_dependencies),
        ("File Structure", check_file_structure),
        ("CLI", check_cli),
        ("Sample Files", check_samples),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            passed = check_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\nError during {name} check: {e}")
            results.append((name, False))
    
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {name}: {status}")
        if not passed:
            all_passed = False
    
    print("=" * 70)
    
    if all_passed:
        print("\n✓ All checks passed! Installation is complete.")
        print("\nNext steps:")
        print("  1. Run: pcd generate-data --out data/processed --seed 42")
        print("  2. Run: pcd train --data data/processed --out models/")
        print("  3. Run: pcd scan samples/")
        return 0
    else:
        print("\n✗ Some checks failed. Please review the errors above.")
        print("\nTroubleshooting:")
        print("  - Make sure you're in the project root directory")
        print("  - Run: pip install -e .")
        print("  - Check SETUP.md for detailed instructions")
        return 1


if __name__ == '__main__':
    sys.exit(main())
