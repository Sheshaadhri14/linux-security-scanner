import json
import os
import sys
import yaml
from datetime import datetime
from checks import run_all_checks


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def calculate_score(results):
    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = sum(1 for r in results if r['status'] == 'FAIL')
    warnings = sum(1 for r in results if r['status'] == 'WARNING')
    errors = sum(1 for r in results if r['status'] == 'ERROR')
    score = round((passed / total) * 100, 1)
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "errors": errors,
        "score": score
    }


def get_risk_level(score):
    if score >= 80:
        return "LOW RISK", "#27ae60"
    elif score >= 60:
        return "MEDIUM RISK", "#f39c12"
    else:
        return "HIGH RISK", "#e74c3c"


def save_json(results, summary, config):
    output = {
        "scanner": config['scanner'],
        "scan_time": datetime.now().isoformat(),
        "summary": summary,
        "results": results
    }
    out_dir = os.path.join(os.path.dirname(__file__), '..', config['report']['output_dir'])
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, config['report']['json_file'])
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"  JSON report saved: {json_path}")
    return output


def print_terminal_summary(results, summary):
    print("\n" + "="*60)
    print("   LINUX SECURITY COMPLIANCE SCANNER")
    print("="*60)

    status_colors = {
        "PASS":    "\033[92m PASS   \033[0m",
        "FAIL":    "\033[91m FAIL   \033[0m",
        "WARNING": "\033[93m WARNING\033[0m",
        "ERROR":   "\033[95m ERROR  \033[0m",
    }

    for r in results:
        color = status_colors.get(r['status'], r['status'])
        cis_id = r.get('id', 'N/A')
        print(f"  [{color}]  {cis_id:<12}  {r['name']}")
        if r['status'] in ['FAIL', 'WARNING']:
            print(f"             ↳ {r['detail']}")
            if 'fix' in r:
                print(f"             ✦ Fix: {r['fix']}")

    print("\n" + "="*60)
    print(f"  COMPLIANCE SCORE : {summary['score']}%")
    print(f"  PASSED           : {summary['passed']}/{summary['total']}")
    print(f"  FAILED           : {summary['failed']}")
    print(f"  WARNINGS         : {summary['warnings']}")
    risk, _ = get_risk_level(summary['score'])
    print(f"  RISK LEVEL       : {risk}")
    print("="*60 + "\n")


def main():
    print("\n[*] Loading configuration...")
    config = load_config()

    print("[*] Running 20 CIS Benchmark security checks...\n")
    results = run_all_checks()

    summary = calculate_score(results)
    print_terminal_summary(results, summary)

    print("[*] Saving reports...")
    full_output = save_json(results, summary, config)

    # import here to avoid circular issues
    from report import generate_html
    generate_html(full_output, config)

    print("\n[✔] Scan complete. Check the reports/ folder.\n")


if __name__ == "__main__":
    main()
