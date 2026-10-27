"""Reporting and output formatting."""

import json
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

from pcd.rules import RuleMatch


@dataclass
class UnitResult:
    """Result for a single code unit."""
    name: str
    lines: List[int]
    score: float
    categories: List[str]
    evidence: List[Dict]
    top_model_features: List[Dict]


@dataclass
class FileResult:
    """Result for a single file."""
    path: str
    verdict: str
    score: float
    parse_ok: bool
    units: List[UnitResult]


@dataclass
class ScanReport:
    """Complete scan report."""
    tool: str = "poisoncode-detector"
    version: str = "0.1.0"
    target: str = ""
    verdict: str = "BENIGN"
    score: float = 0.0
    thresholds: Dict[str, float] = None
    files: List[FileResult] = None
    summary: Dict[str, int] = None
    gate_decision: str = "ALLOW"
    
    def __post_init__(self):
        if self.thresholds is None:
            self.thresholds = {"suspicious": 0.40, "malicious": 0.70}
        if self.files is None:
            self.files = []
        if self.summary is None:
            self.summary = {"files_scanned": 0, "benign": 0, "suspicious": 0, "malicious": 0}


def format_console_report(report: ScanReport, use_color: bool = True) -> str:
    """
    Format report for console output.
    
    Args:
        report: Scan report
        use_color: Whether to use ANSI colors
        
    Returns:
        Formatted string
    """
    # Color codes
    if use_color:
        RED = '\033[91m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
    else:
        RED = YELLOW = GREEN = RESET = BOLD = ''
    
    lines = []
    lines.append(f"{BOLD}PoisonCode Detector {report.version}{RESET} — scanned "
                f"{report.summary['files_scanned']} file(s)")
    lines.append("")
    
    if not report.files:
        lines.append("No files scanned.")
        return '\n'.join(lines)
    
    # Header
    lines.append(f"{'FILE':<50} {'VERDICT':<12} {'SCORE':<8} {'CATEGORIES'}")
    lines.append("-" * 100)
    
    # File results
    for file_result in report.files:
        # Color based on verdict
        if file_result.verdict == "MALICIOUS":
            color = RED
        elif file_result.verdict == "SUSPICIOUS":
            color = YELLOW
        else:
            color = GREEN
        
        # Collect categories from all units
        all_categories = set()
        for unit in file_result.units:
            all_categories.update(unit.categories)
        categories_str = ', '.join(sorted(all_categories)) if all_categories else 'none'
        
        file_path = file_result.path
        if len(file_path) > 47:
            file_path = "..." + file_path[-44:]
        
        lines.append(f"{file_path:<50} {color}{file_result.verdict:<12}{RESET} "
                    f"{file_result.score:<8.2f} {categories_str}")
        
        # Show evidence for non-benign files
        if file_result.verdict != "BENIGN":
            for unit in file_result.units:
                if unit.evidence:
                    for ev in unit.evidence[:5]:  # Top 5 evidence items
                        lines.append(f"  L{ev['line']:<4} {ev['rule']:<12} {ev['why']}")
    
    lines.append("")
    
    # Gate decision
    if report.gate_decision == "BLOCK":
        lines.append(f"{RED}{BOLD}Gate: BLOCK{RESET} (build command not executed)")
    elif report.gate_decision == "WARN":
        lines.append(f"{YELLOW}Gate: WARN{RESET} (build command will run)")
    else:
        lines.append(f"{GREEN}Gate: ALLOW{RESET}")
    
    return '\n'.join(lines)


def format_json_report(report: ScanReport) -> str:
    """
    Format report as JSON.
    
    Args:
        report: Scan report
        
    Returns:
        JSON string
    """
    # Convert to dict
    report_dict = asdict(report)
    return json.dumps(report_dict, indent=2)


def determine_verdict_and_gate(files: List[FileResult], 
                                fail_on: str = "malicious") -> tuple[str, str]:
    """
    Determine overall verdict and gate decision.
    
    Args:
        files: List of file results
        fail_on: 'malicious' or 'suspicious'
        
    Returns:
        Tuple of (verdict, gate_decision)
    """
    if not files:
        return "BENIGN", "ALLOW"
    
    # Check verdicts
    has_malicious = any(f.verdict == "MALICIOUS" for f in files)
    has_suspicious = any(f.verdict == "SUSPICIOUS" for f in files)
    
    if has_malicious:
        verdict = "MALICIOUS"
        gate_decision = "BLOCK"
    elif has_suspicious:
        verdict = "SUSPICIOUS"
        gate_decision = "WARN" if fail_on == "malicious" else "BLOCK"
    else:
        verdict = "BENIGN"
        gate_decision = "ALLOW"
    
    return verdict, gate_decision


def create_scan_report(target: str,
                       file_results: List[FileResult],
                       suspicious_threshold: float,
                       malicious_threshold: float,
                       fail_on: str = "malicious") -> ScanReport:
    """
    Create a complete scan report.
    
    Args:
        target: Scan target
        file_results: List of file results
        suspicious_threshold: Suspicious threshold
        malicious_threshold: Malicious threshold
        fail_on: Fail condition
        
    Returns:
        ScanReport object
    """
    # Calculate summary
    summary = {
        "files_scanned": len(file_results),
        "benign": sum(1 for f in file_results if f.verdict == "BENIGN"),
        "suspicious": sum(1 for f in file_results if f.verdict == "SUSPICIOUS"),
        "malicious": sum(1 for f in file_results if f.verdict == "MALICIOUS")
    }
    
    # Overall verdict and gate
    verdict, gate_decision = determine_verdict_and_gate(file_results, fail_on)
    
    # Max score
    max_score = max((f.score for f in file_results), default=0.0)
    
    report = ScanReport(
        target=target,
        verdict=verdict,
        score=max_score,
        thresholds={
            "suspicious": suspicious_threshold,
            "malicious": malicious_threshold
        },
        files=file_results,
        summary=summary,
        gate_decision=gate_decision
    )
    
    return report
