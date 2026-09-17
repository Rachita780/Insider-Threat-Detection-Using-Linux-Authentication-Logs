import json
import os
import sys

from log_parser import parse_logs


def get_project_root():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(
        os.path.join(current_dir, "..")
    )


def get_default_output_path():
    return os.path.join(
        get_project_root(),
        "behavior_baseline.json"
    )


def extract_hour(timestamp):
    try:
        time_value = timestamp.split()[2]
        return int(time_value.split(":")[0])
    except (IndexError, ValueError):
        return None


def build_allowed_hours(observed_hours):
    allowed_hours = set()

    for hour in observed_hours:
        allowed_hours.add(hour)

        previous_hour = (hour - 1) % 24
        next_hour = (hour + 1) % 24

        allowed_hours.add(previous_hour)
        allowed_hours.add(next_hour)

    return sorted(allowed_hours)


def build_baseline(log_path, output_path=None):
    if output_path is None:
        output_path = get_default_output_path()

    with open(log_path, "r") as file:
        log_lines = file.readlines()

    events = parse_logs(log_lines)

    user_data = {}

    for event in events:
        user = event.get("user", "")
        event_type = event.get("event", "")
        timestamp = event.get("timestamp", "")
        source_ip = event.get("source_ip", "N/A")

        if not user or user == "unknown":
            continue

        if user not in user_data:
            user_data[user] = {
                "login_hours": [],
                "known_ips": set(),
                "successful_login_count": 0
            }

        if event_type == "Successful Login":
            hour = extract_hour(timestamp)

            if hour is not None:
                user_data[user]["login_hours"].append(hour)

            if source_ip and source_ip != "N/A":
                user_data[user]["known_ips"].add(
                    source_ip
                )

            user_data[user][
                "successful_login_count"
            ] += 1

    baseline = {}

    for user, data in user_data.items():
        observed_hours = sorted(
            set(data["login_hours"])
        )

        allowed_hours = build_allowed_hours(
            observed_hours
        )

        baseline[user] = {
            "observed_login_hours": observed_hours,
            "allowed_login_hours": allowed_hours,
            "known_ips": sorted(
                data["known_ips"]
            ),
            "successful_login_count":
                data["successful_login_count"]
        }

    with open(output_path, "w") as file:
        json.dump(
            baseline,
            file,
            indent=4
        )

    print("Behaviour baseline created successfully.")
    print()
    print("Users learned:", len(baseline))
    print("Output file:")
    print(output_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python behavior_baseline.py "
            "<training_log_file>"
        )
        sys.exit(1)

    training_log = sys.argv[1]

    if not os.path.exists(training_log):
        print("Training log not found:")
        print(training_log)
        sys.exit(1)

    build_baseline(training_log)
