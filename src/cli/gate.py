"""CLI compliance gating tool for AntiFine."""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path so we can import src
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanners.iac_audit import run_iac_audit

SEVERITY_RANKS = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

COLORS = {
    "INFORMATIONAL": "\033[94m", # Blue
    "LOW": "\033[96m",           # Cyan
    "MEDIUM": "\033[93m",        # Yellow
    "HIGH": "\033[91m",          # Red
    "CRITICAL": "\033[91m\033[1m", # Bold Red
    "RESET": "\033[0m",
    "GREEN": "\033[92m"
}

def main():
    parser = argparse.ArgumentParser(description="IaC Compliance Gating Tool")
    parser.add_argument("--file", required=True, help="Target file path to scan")
    parser.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum severity threshold to fail the gate"
    )
    parser.add_argument("--min-score", type=int, help="Minimum compliance score (0-100)", required=False)
    
    args = parser.parse_args()
    
    threshold_rank = SEVERITY_RANKS[args.fail_on]
    
    try:
        # We don't want to pollute the DB during a CI/CLI scan
        findings = run_iac_audit(args.file, persist=False)
    except Exception as e:
        print(f"\033[91mError running scan: {e}\033[0m", file=sys.stderr)
        sys.exit(1)
        
    failed = False
    
    if findings:
        for finding_msg, severity in findings:
            sev_upper = severity.upper()
            rank = SEVERITY_RANKS.get(sev_upper, 0)
            
            # Print all findings
            color = COLORS.get(sev_upper, COLORS["RESET"])
            print(f"{color}[{sev_upper}] {finding_msg}{COLORS['RESET']}")
            
            if rank >= threshold_rank:
                failed = True
                
    if args.min_score is not None:
        # Calculate a naive score: Start at 100, deduct based on severity.
        score = 100
        for _, sev in findings:
            sev_upper = sev.upper()
            if sev_upper == "CRITICAL":
                score -= 20
            elif sev_upper == "HIGH":
                score -= 10
            elif sev_upper == "MEDIUM":
                score -= 5
            elif sev_upper == "LOW":
                score -= 1
                
        score = max(0, score)
        print(f"Compliance Score: {score}/100 (Threshold: {args.min_score})")
        if score < args.min_score:
            print(f"{COLORS['HIGH']}[FAIL] Score {score} is below minimum {args.min_score}.{COLORS['RESET']}")
            failed = True
            
    if failed:
        print(f"\n{COLORS['HIGH']}[FAIL] Target failed compliance gate policy (threshold: {args.fail_on}).{COLORS['RESET']}")
        sys.exit(1)
    else:
        print(f"\n{COLORS['GREEN']}[PASS] Target meets compliance gate policy.{COLORS['RESET']}")
        sys.exit(0)

if __name__ == "__main__":
    main()
