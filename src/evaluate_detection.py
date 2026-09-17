import csv
import json
import os

from basic_analyzer import (
    analyze_basic_threats
)

from log_parser import parse_logs

from threat_analyzer import (
    analyze_threats,
    load_config
)


CATEGORIES = {
    "Brute-force",
    "Odd-hour",
    "Excessive sudo",
    "Unusual source IP"
}


def get_project_root():
    current_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    return os.path.abspath(
        os.path.join(
            current_dir,
            ".."
        )
    )


def load_json(path):
    with open(path, "r") as file:
        return json.load(file)


def get_category(issue):
    if "Brute-force" in issue:
        return "Brute-force"

    if "Odd-hour" in issue:
        return "Odd-hour"

    if "sudo" in issue.lower():
        return "Excessive sudo"

    if "Unusual source IP" in issue:
        return "Unusual source IP"

    return None


def threats_to_pairs(threats):
    pairs = set()

    for user, issues in threats.items():
        for issue in issues:
            category = get_category(
                issue
            )

            if category:
                pairs.add(
                    (
                        user,
                        category
                    )
                )

    return pairs


def load_expected_labels(path):
    labels = set()

    with open(path, "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            labels.add(
                (
                    row["username"],
                    row["threat"]
                )
            )

    return labels


def calculate_metrics(
    detected,
    expected,
    users
):
    universe = set()

    for user in users:
        for category in CATEGORIES:
            universe.add(
                (
                    user,
                    category
                )
            )

    true_positive = len(
        detected & expected
    )

    false_positive = len(
        detected - expected
    )

    false_negative = len(
        expected - detected
    )

    true_negative = len(
        universe
        - detected
        - expected
    )

    if (
        true_positive
        + false_positive
    ):
        precision = (
            true_positive
            /
            (
                true_positive
                + false_positive
            )
        )
    else:
        precision = 0

    if (
        true_positive
        + false_negative
    ):
        recall = (
            true_positive
            /
            (
                true_positive
                + false_negative
            )
        )
    else:
        recall = 0

    if precision + recall:
        f1_score = (
            2
            * precision
            * recall
            /
            (
                precision
                + recall
            )
        )
    else:
        f1_score = 0

    if (
        false_positive
        + true_negative
    ):
        false_positive_rate = (
            false_positive
            /
            (
                false_positive
                + true_negative
            )
        )
    else:
        false_positive_rate = 0

    return {
        "TP": true_positive,
        "FP": false_positive,
        "TN": true_negative,
        "FN": false_negative,
        "Precision": precision,
        "Recall": recall,
        "F1": f1_score,
        "FPR": false_positive_rate
    }


def display_results(
    name,
    metrics
):
    print()
    print("=" * 55)
    print(name)
    print("=" * 55)

    print(
        "True Positives     :",
        metrics["TP"]
    )

    print(
        "False Positives    :",
        metrics["FP"]
    )

    print(
        "True Negatives     :",
        metrics["TN"]
    )

    print(
        "False Negatives    :",
        metrics["FN"]
    )

    print(
        "Precision          :",
        f"{metrics['Precision']:.3f}"
    )

    print(
        "Recall             :",
        f"{metrics['Recall']:.3f}"
    )

    print(
        "F1 Score           :",
        f"{metrics['F1']:.3f}"
    )

    print(
        "False Positive Rate:",
        f"{metrics['FPR']:.3f}"
    )


def main():
    root = get_project_root()

    data_dir = os.path.join(
        root,
        "data"
    )

    test_log_path = os.path.join(
        data_dir,
        "large_test_auth.log"
    )

    labels_path = os.path.join(
        data_dir,
        "expected_alerts.csv"
    )

    profiles_path = os.path.join(
        data_dir,
        "synthetic_user_profiles.json"
    )

    baseline_path = os.path.join(
        root,
        "behavior_baseline.json"
    )

    with open(
        test_log_path,
        "r"
    ) as file:
        events = parse_logs(
            file.readlines()
        )

    expected = load_expected_labels(
        labels_path
    )

    synthetic_profiles = load_json(
        profiles_path
    )

    baseline = load_json(
        baseline_path
    )

    config = load_config()

    basic_threats = (
        analyze_basic_threats(
            events,
            config
        )
    )

    improved_threats = (
        analyze_threats(
            events,
            config=config,
            user_profiles=
                synthetic_profiles,
            behavior_baseline=
                baseline
        )
    )

    basic_pairs = threats_to_pairs(
        basic_threats
    )

    improved_pairs = threats_to_pairs(
        improved_threats
    )

    users = {
        event.get("user")
        for event in events
        if event.get("user")
        and event.get("user")
        != "unknown"
    }

    basic_metrics = (
        calculate_metrics(
            basic_pairs,
            expected,
            users
        )
    )

    improved_metrics = (
        calculate_metrics(
            improved_pairs,
            expected,
            users
        )
    )

    display_results(
        "BASIC RULE-BASED DETECTION",
        basic_metrics
    )

    display_results(
        "CONTEXT-AWARE DETECTION",
        improved_metrics
    )

    output_path = os.path.join(
        data_dir,
        "evaluation_results.csv"
    )

    with open(
        output_path,
        "w",
        newline=""
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
            "Approach",
            "TP",
            "FP",
            "TN",
            "FN",
            "Precision",
            "Recall",
            "F1",
            "False Positive Rate"
        ])

        for name, metrics in [
            (
                "Basic Rule-Based",
                basic_metrics
            ),
            (
                "Context-Aware",
                improved_metrics
            )
        ]:
            writer.writerow([
                name,
                metrics["TP"],
                metrics["FP"],
                metrics["TN"],
                metrics["FN"],
                round(
                    metrics[
                        "Precision"
                    ],
                    3
                ),
                round(
                    metrics[
                        "Recall"
                    ],
                    3
                ),
                round(
                    metrics[
                        "F1"
                    ],
                    3
                ),
                round(
                    metrics[
                        "FPR"
                    ],
                    3
                )
            ])

    print()
    print(
        "Evaluation results saved to:"
    )
    print(output_path)


if __name__ == "__main__":
    main()
