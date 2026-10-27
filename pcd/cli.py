"""Command-line interface for PoisonCode Detector."""

import sys
import argparse
from pathlib import Path
from typing import Optional
import yaml

from pcd import __version__
from pcd.scanner import scan_target, CodeUnit
from pcd.rules import RuleEngine
from pcd.model import PCDModel, evaluate_model, leave_one_family_out_eval
from pcd.report import (
    UnitResult, FileResult, create_scan_report,
    format_console_report, format_json_report
)
from pcd.gate import build_gate, compile_python_file


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from pcd.yaml."""
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    elif Path('pcd.yaml').exists():
        with open('pcd.yaml', 'r') as f:
            return yaml.safe_load(f)
    else:
        # Default config
        return {
            'suspicious_threshold': 0.40,
            'malicious_threshold': 0.70,
            'fail_on': 'malicious',
            'model_path': 'models/pcd_model.joblib',
            'ignore_globs': ['**/.git/**', '**/venv/**', '**/node_modules/**', '**/__pycache__/**']
        }


def cmd_scan(args):
    """Scan command implementation."""
    config = load_config(args.config)
    
    # Load model
    model_path = args.model or config.get('model_path', 'models/pcd_model.joblib')
    if not Path(model_path).exists():
        print(f"Error: Model not found at {model_path}", file=sys.stderr)
        print("Run 'pcd train' first to create the model.", file=sys.stderr)
        return 3
    
    try:
        model = PCDModel.load(model_path)
    except Exception as e:
        print(f"Error loading model: {e}", file=sys.stderr)
        print("The model may be incompatible. Please retrain with:", file=sys.stderr)
        print("  pcd train --data data/processed --out models/", file=sys.stderr)
        return 3
    
    # Scan target
    ignore_patterns = config.get('ignore_globs', [])
    scanned_files = scan_target(args.target, ignore_patterns)
    
    if not scanned_files:
        print(f"No Python files found in {args.target}", file=sys.stderr)
        return 3
    
    # Initialize rule engine
    rule_engine = RuleEngine()
    
    # Analyze each file
    file_results = []
    for scan_file in scanned_files:
        unit_results = []
        file_score = 0.0
        
        for unit in scan_file.units:
            # Get ML score
            try:
                ml_score, ml_verdict = model.predict(unit.code)
            except Exception as e:
                # Model compatibility issue - use conservative default
                print(f"Warning: Model prediction failed ({e}), using rules only", file=sys.stderr)
                ml_score = 0.0  # Default to benign
            
            # Check rules
            rule_matches = rule_engine.check_code(unit.code, unit.start_line)
            
            # Calculate rule floor - but only if ML score is also somewhat elevated
            # This prevents false positives on legitimate code that uses risky APIs
            rule_floor = 0.0
            critical_count = sum(1 for m in rule_matches if m.severity == "critical")
            high_count = sum(1 for m in rule_matches if m.severity == "high")
            
            # Only apply rule floor if ML model also thinks it's somewhat suspicious
            if ml_score > 0.3:  # ML model is somewhat suspicious
                if critical_count >= 2:  # Multiple critical rules
                    rule_floor = max(rule_floor, 0.75)
                elif critical_count >= 1:
                    rule_floor = max(rule_floor, 0.55)
                elif high_count >= 2:
                    rule_floor = max(rule_floor, 0.45)
            
            # Final score - weighted combination
            # If ML is confident (very high or very low), trust it more
            if ml_score > 0.8 or ml_score < 0.2:
                # ML is confident, use it primarily
                unit_score = ml_score * 0.85 + rule_floor * 0.15
            else:
                # ML is uncertain, balance with rules
                unit_score = max(ml_score, rule_floor)
            file_score = max(file_score, unit_score)
            
            # Verdict
            if unit_score < model.benign_threshold:
                unit_verdict = "BENIGN"
            elif unit_score >= model.malicious_threshold:
                unit_verdict = "MALICIOUS"
            elif unit_score >= model.suspicious_threshold:
                unit_verdict = "SUSPICIOUS"
            else:
                unit_verdict = "BENIGN"
            
            # Extract categories
            categories = list(set(match.family for match in rule_matches))
            
            # Format evidence
            evidence = [
                {
                    'rule': match.rule_id,
                    'severity': match.severity,
                    'line': match.line,
                    'snippet': match.snippet,
                    'why': match.why
                }
                for match in rule_matches[:5]  # Top 5
            ]
            
            # Top model features (simplified - just placeholder)
            top_features = []
            
            unit_results.append(UnitResult(
                name=unit.name,
                lines=[unit.start_line, unit.end_line],
                score=unit_score,
                categories=categories,
                evidence=evidence,
                top_model_features=top_features
            ))
        
        # File verdict
        if file_score < model.benign_threshold:
            file_verdict = "BENIGN"
        elif file_score >= model.malicious_threshold:
            file_verdict = "MALICIOUS"
        elif file_score >= model.suspicious_threshold:
            file_verdict = "SUSPICIOUS"
        else:
            file_verdict = "BENIGN"
        
        file_results.append(FileResult(
            path=scan_file.path,
            verdict=file_verdict,
            score=file_score,
            parse_ok=scan_file.parse_ok,
            units=unit_results
        ))
    
    # Create report
    report = create_scan_report(
        target=args.target,
        file_results=file_results,
        suspicious_threshold=model.suspicious_threshold,
        malicious_threshold=model.malicious_threshold,
        fail_on=config.get('fail_on', 'malicious')
    )
    
    # Output report
    if args.format == 'json':
        output = format_json_report(report)
        if args.out:
            with open(args.out, 'w') as f:
                f.write(output)
        else:
            print(output)
    else:
        # Console format
        output = format_console_report(report, use_color=sys.stdout.isatty())
        print(output)
        
        if args.out:
            with open(args.out, 'w') as f:
                f.write(output)
    
    # Return appropriate exit code
    if report.verdict == "MALICIOUS":
        return 2
    elif report.verdict == "SUSPICIOUS":
        return 1
    else:
        return 0


def cmd_build(args):
    """Build command implementation."""
    config = load_config(args.config)
    
    # First, scan the target
    class ScanArgs:
        def __init__(self):
            self.target = args.target
            self.model = args.model
            self.config = args.config
            self.format = 'console'
            self.out = None
    
    scan_args = ScanArgs()
    
    # Load model
    model_path = args.model or config.get('model_path', 'models/pcd_model.joblib')
    if not Path(model_path).exists():
        print(f"Error: Model not found at {model_path}", file=sys.stderr)
        return 3
    
    model = PCDModel.load(model_path)
    
    # Scan
    ignore_patterns = config.get('ignore_globs', [])
    scanned_files = scan_target(args.target, ignore_patterns)
    rule_engine = RuleEngine()
    
    # Analyze files (same logic as scan)
    file_results = []
    for scan_file in scanned_files:
        unit_results = []
        file_score = 0.0
        
        for unit in scan_file.units:
            ml_score, ml_verdict = model.predict(unit.code)
            rule_matches = rule_engine.check_code(unit.code, unit.start_line)
            
            # Calculate rule floor - same logic as cmd_scan
            rule_floor = 0.0
            critical_count = sum(1 for m in rule_matches if m.severity == "critical")
            high_count = sum(1 for m in rule_matches if m.severity == "high")
            
            # Only apply rule floor if ML model also thinks it's somewhat suspicious
            if ml_score > 0.3:
                if critical_count >= 2:
                    rule_floor = max(rule_floor, 0.75)
                elif critical_count >= 1:
                    rule_floor = max(rule_floor, 0.55)
                elif high_count >= 2:
                    rule_floor = max(rule_floor, 0.45)
            
            # Final score - trust ML when confident
            if ml_score > 0.8 or ml_score < 0.2:
                unit_score = ml_score * 0.85 + rule_floor * 0.15
            else:
                unit_score = max(ml_score, rule_floor)
            file_score = max(file_score, unit_score)
            
            if unit_score >= model.malicious_threshold:
                unit_verdict = "MALICIOUS"
            elif unit_score >= model.suspicious_threshold:
                unit_verdict = "SUSPICIOUS"
            else:
                unit_verdict = "BENIGN"
            
            categories = list(set(match.family for match in rule_matches))
            evidence = [
                {
                    'rule': match.rule_id,
                    'severity': match.severity,
                    'line': match.line,
                    'snippet': match.snippet,
                    'why': match.why
                }
                for match in rule_matches[:5]
            ]
            
            unit_results.append(UnitResult(
                name=unit.name,
                lines=[unit.start_line, unit.end_line],
                score=unit_score,
                categories=categories,
                evidence=evidence,
                top_model_features=[]
            ))
        
        if file_score < model.benign_threshold:
            file_verdict = "BENIGN"
        elif file_score >= model.malicious_threshold:
            file_verdict = "MALICIOUS"
        elif file_score >= model.suspicious_threshold:
            file_verdict = "SUSPICIOUS"
        else:
            file_verdict = "BENIGN"
        
        file_results.append(FileResult(
            path=scan_file.path,
            verdict=file_verdict,
            score=file_score,
            parse_ok=scan_file.parse_ok,
            units=unit_results
        ))
    
    # Create report
    fail_on = args.fail_on or config.get('fail_on', 'malicious')
    report = create_scan_report(
        target=args.target,
        file_results=file_results,
        suspicious_threshold=model.suspicious_threshold,
        malicious_threshold=model.malicious_threshold,
        fail_on=fail_on
    )
    
    # Print report
    output = format_console_report(report, use_color=sys.stdout.isatty())
    print(output)
    
    # Execute build gate
    build_command = args.command if args.command else None
    exit_code = build_gate(report, build_command, fail_on)
    
    return exit_code


def cmd_compile(args):
    """Compile command implementation."""
    # First scan the file
    class ScanArgs:
        def __init__(self):
            self.target = args.file
            self.model = args.model
            self.config = args.config
            self.format = 'console'
            self.out = None
    
    scan_args = ScanArgs()
    scan_exit = cmd_scan(scan_args)
    
    # If malicious, don't compile
    if scan_exit == 2:
        print(f"Compilation blocked: {args.file} contains malicious code", file=sys.stderr)
        return 2
    
    # Compile
    compile_exit = compile_python_file(args.file)
    
    # Return worst exit code
    return max(scan_exit, compile_exit)


def cmd_generate_data(args):
    """Generate dataset command."""
    import sys
    from pathlib import Path
    # Add data directory to path
    data_dir = Path(__file__).parent.parent / 'data'
    if str(data_dir) not in sys.path:
        sys.path.insert(0, str(data_dir.parent))
    from data.generate_dataset import generate_dataset
    
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating dataset with seed {args.seed}...")
    print(f"  Benign samples: {args.n_benign}")
    print(f"  Malicious samples: {args.n_malicious}")
    
    dataset_path = generate_dataset(
        output_dir=str(output_dir),
        n_benign=args.n_benign,
        n_malicious=args.n_malicious,
        seed=args.seed
    )
    
    print(f"Dataset saved to {dataset_path}")
    return 0


def cmd_train(args):
    """Train model command."""
    dataset_path = Path(args.data) / 'dataset.csv'
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}", file=sys.stderr)
        return 3
    
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    model = PCDModel()
    print("Training model...")
    metrics = model.train(str(dataset_path), seed=args.seed)
    
    print("\nTraining Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    
    # Save model
    model_path = output_dir / 'pcd_model.joblib'
    model.save(str(model_path), str(dataset_path))
    print(f"\nModel saved to {model_path}")
    
    return 0


def cmd_eval(args):
    """Evaluate model command."""
    dataset_path = Path(args.data) / 'dataset.csv'
    model_path = Path(args.model)
    
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}", file=sys.stderr)
        return 3
    
    if not model_path.exists():
        print(f"Error: Model not found at {model_path}", file=sys.stderr)
        return 3
    
    # Load model
    model = PCDModel.load(str(model_path))
    
    # Evaluate
    output_dir = Path(args.out) if args.out else Path('reports')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    metrics = evaluate_model(model, str(dataset_path), str(output_dir))
    
    # LOFO evaluation
    if not args.skip_lofo:
        print("\nRunning leave-one-family-out evaluation...")
        lofo_results = leave_one_family_out_eval(str(dataset_path), str(output_dir), seed=42)
        print(f"LOFO mean recall: {lofo_results['mean_recall']:.3f}")
    
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='PoisonCode Detector - Detect malicious code patterns',
        prog='pcd'
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files for malicious code')
    scan_parser.add_argument('target', help='File, directory, or - for stdin')
    scan_parser.add_argument('--model', help='Path to model file')
    scan_parser.add_argument('--config', help='Path to config file')
    scan_parser.add_argument('--format', choices=['console', 'json'], default='console',
                            help='Output format')
    scan_parser.add_argument('--out', help='Output file')
    
    # Build command
    build_parser = subparsers.add_parser('build', help='Scan and gate a build')
    build_parser.add_argument('--target', required=True, help='Directory to scan')
    build_parser.add_argument('--model', help='Path to model file')
    build_parser.add_argument('--config', help='Path to config file')
    build_parser.add_argument('--fail-on', choices=['malicious', 'suspicious'],
                             help='When to block the build')
    build_parser.add_argument('command', nargs='*', help='Build command to execute')
    
    # Compile command
    compile_parser = subparsers.add_parser('compile', help='Scan and compile a Python file')
    compile_parser.add_argument('file', help='Python file to compile')
    compile_parser.add_argument('--model', help='Path to model file')
    compile_parser.add_argument('--config', help='Path to config file')
    
    # Generate-data command
    gen_parser = subparsers.add_parser('generate-data', help='Generate training dataset')
    gen_parser.add_argument('--out', required=True, help='Output directory')
    gen_parser.add_argument('--n-benign', type=int, default=3000,
                           help='Number of benign samples')
    gen_parser.add_argument('--n-malicious', type=int, default=3000,
                           help='Number of malicious samples')
    gen_parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the model')
    train_parser.add_argument('--data', required=True, help='Dataset directory')
    train_parser.add_argument('--out', required=True, help='Output directory for model')
    train_parser.add_argument('--seed', type=int, default=42, help='Random seed')
    
    # Eval command
    eval_parser = subparsers.add_parser('eval', help='Evaluate the model')
    eval_parser.add_argument('--data', required=True, help='Dataset directory')
    eval_parser.add_argument('--model', required=True, help='Model file')
    eval_parser.add_argument('--out', help='Output directory for reports')
    eval_parser.add_argument('--skip-lofo', action='store_true',
                            help='Skip leave-one-family-out evaluation')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Dispatch to command handlers
    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'build':
        return cmd_build(args)
    elif args.command == 'compile':
        return cmd_compile(args)
    elif args.command == 'generate-data':
        return cmd_generate_data(args)
    elif args.command == 'train':
        return cmd_train(args)
    elif args.command == 'eval':
        return cmd_eval(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
