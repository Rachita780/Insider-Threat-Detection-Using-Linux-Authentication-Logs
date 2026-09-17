import json
import os
from datetime import datetime, timedelta


def get_project_root():
    current_dir = os.path.dirname(os.path.abspath(__file__))

    return os.path.abspath(
        os.path.join(current_dir, "..")
    )


def load_json_file(filename, default_value):
    file_path = os.path.join(
        get_project_root(),
        filename
    )

    try:
        with open(file_path, "r") as file:
            return json.load(file)

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):
        return default_value


def load_config():
    return load_json_file(
        "config.json",
        {
            "brute_force_threshold": 5,
            "brute_force_window_minutes": 2,
            "sudo_threshold": 3,
            "odd_hour_start": 22,
            "odd_hour_end": 6,
            "brute_force_weight": 50,
            "sudo_weight": 40,
            "odd_hour_weight": 30,
            "unusual_ip_weight": 20
        }
    )


def load_user_profiles():
    return load_json_file(
        "user_profiles.json",
        {}
    )


def load_behavior_baseline():
    return load_json_file(
        "behavior_baseline.json",
        {}
    )


def is_outside_working_hours(
    hour,
    work_start,
    work_end
):
    if work_start < work_end:
        return not (
            work_start <= hour < work_end
        )

    return not (
        hour >= work_start
        or hour < work_end
    )


def parse_timestamp(timestamp):
    try:
        current_year = datetime.now().year

        full_timestamp = (
            f"{current_year} {timestamp}"
        )

        return datetime.strptime(
            full_timestamp,
            "%Y %b %d %H:%M:%S"
        )

    except ValueError:
        return None


def detect_brute_force(
    timestamps,
    threshold,
    window_minutes
):
    valid_times = [
        time
        for time in timestamps
        if time is not None
    ]

    valid_times.sort()

    if len(valid_times) < threshold:
        return False, 0, None, None

    window = timedelta(
        minutes=window_minutes
    )

    for start_index in range(
        len(valid_times)
    ):
        start_time = valid_times[
            start_index
        ]

        count = 0
        end_time = start_time

        for current_time in valid_times[
            start_index:
        ]:
            if (
                current_time - start_time
                <= window
            ):
                count += 1
                end_time = current_time
            else:
                break

        if count >= threshold:
            return (
                True,
                count,
                start_time,
                end_time
            )

    return False, 0, None, None


def get_known_ips(
    user,
    user_profiles,
    behavior_baseline
):
    known_ips = set()

    profile = user_profiles.get(
        user,
        {}
    )

    for ip_address in profile.get(
        "trusted_ips",
        []
    ):
        known_ips.add(ip_address)

    baseline = behavior_baseline.get(
        user,
        {}
    )

    for ip_address in baseline.get(
        "known_ips",
        []
    ):
        known_ips.add(ip_address)

    return known_ips


def check_login_time(
    user,
    hour,
    time_value,
    user_profiles,
    behavior_baseline,
    default_start,
    default_end
):
    if user in user_profiles:
        profile = user_profiles[user]

        work_start = profile.get(
            "work_start",
            8
        )

        work_end = profile.get(
            "work_end",
            18
        )

        if is_outside_working_hours(
            hour,
            work_start,
            work_end
        ):
            return (
                "Odd-hour login: "
                f"successful login observed at "
                f"{time_value}. "
                f"Configured working hours for "
                f"{user}: "
                f"{work_start:02d}:00-"
                f"{work_end:02d}:00."
            )

        return None

    baseline = behavior_baseline.get(
        user,
        {}
    )

    allowed_hours = baseline.get(
        "allowed_login_hours",
        []
    )

    if allowed_hours:
        if hour not in allowed_hours:
            return (
                "Odd-hour login: "
                f"successful login observed at "
                f"{time_value}. "
                "The login hour is outside the "
                "historically learned login-hour "
                f"pattern for {user}."
            )

        return None

    if (
        hour >= default_start
        or hour < default_end
    ):
        return (
            "Odd-hour login: "
            f"successful login observed at "
            f"{time_value}. "
            "Default odd-hour period: "
            f"{default_start:02d}:00-"
            f"{default_end:02d}:00."
        )

    return None


def analyze_threats(
    events,
    config=None,
    user_profiles=None,
    behavior_baseline=None
):
    if config is None:
        config = load_config()

    if user_profiles is None:
        user_profiles = (
            load_user_profiles()
        )

    if behavior_baseline is None:
        behavior_baseline = (
            load_behavior_baseline()
        )

    brute_force_threshold = config.get(
        "brute_force_threshold",
        5
    )

    brute_force_window = config.get(
        "brute_force_window_minutes",
        2
    )

    sudo_threshold = config.get(
        "sudo_threshold",
        3
    )

    default_odd_hour_start = config.get(
        "odd_hour_start",
        22
    )

    default_odd_hour_end = config.get(
        "odd_hour_end",
        6
    )

    detected_threats = {}
    failed_logins = {}
    sudo_usage = {}

    unusual_ip_alerted = set()

    for event in events:
        user = event.get("user", "")
        event_type = event.get(
            "event",
            ""
        )

        timestamp = event.get(
            "timestamp",
            ""
        )

        source_ip = event.get(
            "source_ip",
            "N/A"
        )

        if (
            not user
            or user == "unknown"
        ):
            continue

        if event_type == "Failed Login":
            parsed_time = parse_timestamp(
                timestamp
            )

            failed_logins.setdefault(
                user,
                []
            )

            failed_logins[user].append(
                parsed_time
            )

        if event_type == "Successful Login":
            try:
                time_value = (
                    timestamp.split()[2]
                )

                hour = int(
                    time_value.split(":")[0]
                )

                time_alert = check_login_time(
                    user,
                    hour,
                    time_value,
                    user_profiles,
                    behavior_baseline,
                    default_odd_hour_start,
                    default_odd_hour_end
                )

                if time_alert:
                    detected_threats.setdefault(
                        user,
                        []
                    )

                    detected_threats[user].append(
                        time_alert
                    )

                known_ips = get_known_ips(
                    user,
                    user_profiles,
                    behavior_baseline
                )

                if (
                    source_ip
                    and source_ip != "N/A"
                    and known_ips
                    and source_ip not in known_ips
                    and user not in
                    unusual_ip_alerted
                ):
                    detected_threats.setdefault(
                        user,
                        []
                    )

                    explanation = (
                        "Unusual source IP: "
                        f"successful login from "
                        f"{source_ip}. "
                        "This IP is not present in "
                        "the trusted or historically "
                        "learned IP list for "
                        f"{user}."
                    )

                    detected_threats[user].append(
                        explanation
                    )

                    unusual_ip_alerted.add(
                        user
                    )

            except (
                IndexError,
                ValueError
            ):
                pass

        if event_type == "Privilege Usage":
            sudo_usage[user] = (
                sudo_usage.get(user, 0)
                + 1
            )

    for user, timestamps in (
        failed_logins.items()
    ):
        (
            detected,
            count,
            start_time,
            end_time
        ) = detect_brute_force(
            timestamps,
            brute_force_threshold,
            brute_force_window
        )

        if detected:
            detected_threats.setdefault(
                user,
                []
            )

            start_display = (
                start_time.strftime(
                    "%H:%M:%S"
                )
            )

            end_display = (
                end_time.strftime(
                    "%H:%M:%S"
                )
            )

            explanation = (
                f"Brute-force: {count} failed "
                "login attempts observed within "
                f"{brute_force_window} minutes "
                f"({start_display}-"
                f"{end_display}). "
                "Configured threshold: "
                f"{brute_force_threshold} "
                "failed attempts."
            )

            detected_threats[user].append(
                explanation
            )

    for user, count in sudo_usage.items():
        if count >= sudo_threshold:
            detected_threats.setdefault(
                user,
                []
            )

            explanation = (
                "Excessive sudo usage: "
                f"{count} privilege-usage "
                "events observed. "
                "Configured threshold: "
                f"{sudo_threshold} sudo events."
            )

            detected_threats[user].append(
                explanation
            )

    return detected_threats


if __name__ == "__main__":
    print(
        "Threat Analyzer module loaded "
        "successfully."
    )
