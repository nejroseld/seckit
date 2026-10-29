"""Measure findings on labeled clean and vulnerable fixtures (not a general quality claim)."""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guardkit.scanning import scan  # noqa: E402

HERE = Path(__file__).parent
LABELS = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))


def ratio(numerator: int, denominator: int):
    return numerator / denominator if denominator else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trivy", required=True, help="path/name of locally installed Trivy executable")
    parser.add_argument("--semgrep", required=True, help="path/name of locally installed Semgrep executable")
    args = parser.parse_args()

    positive_root = HERE / LABELS["positive_fixture"]
    clean_root = HERE / LABELS["clean_fixture"]
    started = time.perf_counter()
    positive = scan(positive_root, args.trivy, args.semgrep)
    clean = scan(clean_root, args.trivy, args.semgrep)
    hard_negative = scan(HERE / LABELS["hard_negative_fixture"], args.trivy, args.semgrep)
    elapsed = time.perf_counter() - started
    if positive["errors"] or clean["errors"] or hard_negative["errors"]:
        print(json.dumps({"status": "incomplete", "precision": None, "recall": None,
                          "errors": {"positive": positive["errors"], "clean": clean["errors"], "hard_negative": hard_negative["errors"]}}, indent=2))
        return 2

    expected = {(item["rule_id"], item["file"], item["line"]) for item in LABELS["expected_rule_matches"]}
    code = [finding for finding in positive["findings"] if finding["category"] == "code"]
    observed = {(finding["rule_id"], finding["file"], finding["line"]) for finding in code}
    true_positive = len(expected & observed)
    clean_code_count = sum(f["category"] == "code" for f in clean["findings"])
    hard_negative_count = sum(f["category"] == "code" for f in hard_negative["findings"])
    false_positive = len(observed - expected) + clean_code_count + hard_negative_count
    false_negative = len(expected - observed)
    code_metrics = {
        "expected": len(expected), "true_positive": true_positive,
        "false_positive": false_positive, "false_negative": false_negative,
        "precision": ratio(true_positive, true_positive + false_positive),
        "recall": ratio(true_positive, true_positive + false_negative),
    }

    p0_expected = {(f["rule_id"], f["file"], f["line"]) for f in LABELS["expected_p0_matches"]}
    p0_actual = {(f["rule_id"], f["file"], f["line"]) for f in positive["findings"] if f["priority"] == "P0"}
    p0_tp = len(p0_expected & p0_actual)
    p0_fp = len(p0_actual - p0_expected) + sum(f["priority"] == "P0" for f in clean["findings"] + hard_negative["findings"])
    p0_metrics = {"expected": len(p0_expected), "true_positive": p0_tp, "false_positive": p0_fp,
                  "false_negative": len(p0_expected - p0_actual),
                  "precision": ratio(p0_tp, p0_tp + p0_fp), "recall": ratio(p0_tp, len(p0_expected))}
    expected_categories = LABELS["expected_scanner_categories"]
    positive_categories = {finding["category"] for finding in positive["findings"]}
    clean_categories = {finding["category"] for finding in clean["findings"]}
    category_metrics = {
        category: {"expected": 1, "detected": int(category in positive_categories),
                   "missed": int(category not in positive_categories),
                   "clean_fixture_findings": sum(f["category"] == category for f in clean["findings"])}
        for category in expected_categories
    }
    category_recall = ratio(sum(row["detected"] for row in category_metrics.values()), len(category_metrics))
    print(json.dumps({
        "fixture_pair": [str(positive_root.relative_to(ROOT)), str(clean_root.relative_to(ROOT))],
        "static_rule_precision_recall": code_metrics,
        "clean_code_findings": clean_code_count,
        "p0_precision_recall": p0_metrics,
        "hard_negative_code_findings": hard_negative_count,
        "hard_negative_note": "Safe Set-allowlisted redirect; reports here count as false positives, not hidden exclusions.",
        "scanner_category_recall": {"categories": category_metrics, "recall": category_recall},
        "elapsed_seconds": round(elapsed, 3), "setup_seconds": None,
        "setup_note": "Tool installation and Trivy database provisioning are external and unmeasured.",
        "errors": {"positive": positive["errors"], "clean": clean["errors"], "hard_negative": hard_negative["errors"]},
    }, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
