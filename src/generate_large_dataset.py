import csv
import json
import os
import random

from datetime import datetime, timedelta


random.seed(42)

NUM_USERS = 100
TRAIN_EVENTS_PER_USER = 20
TEST_EVENTS_PER_USER = 30

DAY_HOURS = list(
    range(8, 18)
)

NIGHT_HOURS = [
    21,
    22,
    23,
    0,
    1,
    2,
    3,
    4
]


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


def make_user(number):
    return f"user{number:03d}"


def get_normal_ip(number):
    third_octet = (
        (number - 1) // 250
    )

    fourth_octet = (
        ((number - 1) % 250)
        + 1
    )

    return (
        f"10.0.{third_octet}."
        f"{fourth_octet}"
    )


def format_timestamp(dt):
    return dt.strftime(
        "%b %d %H:%M:%S"
    )


def ssh_line(
    dt,
    user,
    ip_address,
    success=True
):
    pid = random.randint(
        1000,
        9999
    )

    if success:
        message = (
            f"Accepted password for {user} "
            f"from {ip_address} "
            "port 22 ssh2"
        )
    else:
        message = (
            f"Failed password for {user} "
            f"from {ip_address} "
            "port 22 ssh2"
        )

    return (
        f"{format_timestamp(dt)} "
        f"kali sshd[{pid}]: "
        f"{message}"
    )


def sudo_line(
    dt,
    user
):
    return (
        f"{format_timestamp(dt)} "
        f"kali sudo: "
        f"{user} : "
        "TTY=pts/0 ; "
        f"PWD=/home/{user} ; "
        "USER=root ; "
        "COMMAND=/usr/bin/id"
    )


def add_entry(
    collection,
    dt,
    line
):
    collection.append(
        (dt, line)
    )


def main():
    root = get_project_root()

    data_dir = os.path.join(
        root,
        "data"
    )

    os.makedirs(
        data_dir,
        exist_ok=True
    )

    training_entries = []
    test_entries = []
    expected_alerts = []

    learned_night_users = {
        make_user(number)
        for number in range(
            91,
            96
        )
    }

    profile_night_users = {
        make_user(number)
        for number in range(
            96,
            101
        )
    }

    all_night_users = (
        learned_night_users
        | profile_night_users
    )

    training_start = datetime(
        2026,
        6,
        1
    )

    test_start = datetime(
        2026,
        6,
        20
    )

    for number in range(
        1,
        NUM_USERS + 1
    ):
        user = make_user(number)
        normal_ip = get_normal_ip(
            number
        )

        if user in all_night_users:
            normal_hours = NIGHT_HOURS
        else:
            normal_hours = DAY_HOURS

        for event_number in range(
            TRAIN_EVENTS_PER_USER
        ):
            day_offset = (
                event_number % 10
            )

            hour = normal_hours[
                event_number
                % len(normal_hours)
            ]

            dt = (
                training_start
                + timedelta(
                    days=day_offset
                )
            ).replace(
                hour=hour,
                minute=random.randint(
                    0,
                    59
                ),
                second=random.randint(
                    0,
                    59
                )
            )

            add_entry(
                training_entries,
                dt,
                ssh_line(
                    dt,
                    user,
                    normal_ip,
                    True
                )
            )

        for event_number in range(
            TEST_EVENTS_PER_USER
        ):
            day_offset = (
                event_number % 5
            )

            hour = random.choice(
                normal_hours
            )

            dt = (
                test_start
                + timedelta(
                    days=day_offset
                )
            ).replace(
                hour=hour,
                minute=random.randint(
                    0,
                    59
                ),
                second=random.randint(
                    0,
                    59
                )
            )

            add_entry(
                test_entries,
                dt,
                ssh_line(
                    dt,
                    user,
                    normal_ip,
                    True
                )
            )

    # --------------------------------
    # Brute-force users: user001-010
    # --------------------------------

    for number in range(
        1,
        11
    ):
        user = make_user(number)
        normal_ip = get_normal_ip(
            number
        )

        start_time = datetime(
            2026,
            6,
            21,
            10,
            0,
            0
        )

        for attempt in range(5):
            dt = (
                start_time
                + timedelta(
                    seconds=attempt * 10
                )
            )

            add_entry(
                test_entries,
                dt,
                ssh_line(
                    dt,
                    user,
                    normal_ip,
                    False
                )
            )

        expected_alerts.append(
            (user, "Brute-force")
        )

    # --------------------------------
    # Spread failures: user011-020
    #
    # These SHOULD NOT be classified
    # as brute-force by context-aware
    # detection.
    # --------------------------------

    for number in range(
        11,
        21
    ):
        user = make_user(number)
        normal_ip = get_normal_ip(
            number
        )

        failure_hours = [
            8,
            10,
            12,
            14,
            16
        ]

        for hour in failure_hours:
            dt = datetime(
                2026,
                6,
                21,
                hour,
                0,
                0
            )

            add_entry(
                test_entries,
                dt,
                ssh_line(
                    dt,
                    user,
                    normal_ip,
                    False
                )
            )

    # --------------------------------
    # Odd-hour users: user021-030
    # --------------------------------

    for number in range(
        21,
        31
    ):
        user = make_user(number)
        normal_ip = get_normal_ip(
            number
        )

        dt = datetime(
            2026,
            6,
            22,
            23,
            45,
            0
        )

        add_entry(
            test_entries,
            dt,
            ssh_line(
                dt,
                user,
                normal_ip,
                True
            )
        )

        expected_alerts.append(
            (user, "Odd-hour")
        )

    # --------------------------------
    # Excessive sudo: user031-040
    # --------------------------------

    for number in range(
        31,
        41
    ):
        user = make_user(number)

        start_time = datetime(
            2026,
            6,
            22,
            11,
            0,
            0
        )

        for event_number in range(3):
            dt = (
                start_time
                + timedelta(
                    minutes=event_number
                )
            )

            add_entry(
                test_entries,
                dt,
                sudo_line(
                    dt,
                    user
                )
            )

        expected_alerts.append(
            (
                user,
                "Excessive sudo"
            )
        )

    # --------------------------------
    # New source IP: user041-050
    # --------------------------------

    for number in range(
        41,
        51
    ):
        user = make_user(number)

        new_ip = (
            f"172.16.0."
            f"{number}"
        )

        dt = datetime(
            2026,
            6,
            23,
            10,
            30,
            0
        )

        add_entry(
            test_entries,
            dt,
            ssh_line(
                dt,
                user,
                new_ip,
                True
            )
        )

        expected_alerts.append(
            (
                user,
                "Unusual source IP"
            )
        )

    # --------------------------------
    # Small amount of normal sudo
    # activity. This should NOT reach
    # the threshold.
    # --------------------------------

    for number in range(
        51,
        61
    ):
        user = make_user(number)

        dt = datetime(
            2026,
            6,
            23,
            12,
            0,
            0
        )

        add_entry(
            test_entries,
            dt,
            sudo_line(
                dt,
                user
            )
        )

    training_entries.sort(
        key=lambda item: item[0]
    )

    test_entries.sort(
        key=lambda item: item[0]
    )

    training_path = os.path.join(
        data_dir,
        "baseline_training.log"
    )

    test_path = os.path.join(
        data_dir,
        "large_test_auth.log"
    )

    labels_path = os.path.join(
        data_dir,
        "expected_alerts.csv"
    )

    profile_path = os.path.join(
        data_dir,
        "synthetic_user_profiles.json"
    )

    with open(
        training_path,
        "w"
    ) as file:
        for _, line in training_entries:
            file.write(
                line + "\n"
            )

    with open(
        test_path,
        "w"
    ) as file:
        for _, line in test_entries:
            file.write(
                line + "\n"
            )

    with open(
        labels_path,
        "w",
        newline=""
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
            "username",
            "threat"
        ])

        for row in expected_alerts:
            writer.writerow(row)

    synthetic_profiles = {}

    for user in sorted(
        profile_night_users
    ):
        synthetic_profiles[user] = {
            "work_start": 20,
            "work_end": 6,
            "trusted_ips": []
        }

    with open(
        profile_path,
        "w"
    ) as file:
        json.dump(
            synthetic_profiles,
            file,
            indent=4
        )

    print(
        "Large synthetic dataset "
        "created successfully."
    )

    print()

    print(
        "Users:",
        NUM_USERS
    )

    print(
        "Training events:",
        len(training_entries)
    )

    print(
        "Test events:",
        len(test_entries)
    )

    print(
        "Expected suspicious "
        "user-threat pairs:",
        len(expected_alerts)
    )

    print()

    print(
        "Training log:",
        training_path
    )

    print(
        "Test log:",
        test_path
    )

    print(
        "Ground-truth labels:",
        labels_path
    )

    print(
        "Synthetic profiles:",
        profile_path
    )


if __name__ == "__main__":
    main()
