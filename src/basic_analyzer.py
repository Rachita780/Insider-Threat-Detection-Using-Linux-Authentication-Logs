from threat_analyzer import load_config


def analyze_basic_threats(
    events,
    config=None
):
    if config is None:
        config = load_config()

    brute_force_threshold = config.get(
        "brute_force_threshold",
        5
    )

    sudo_threshold = config.get(
        "sudo_threshold",
        3
    )

    odd_hour_start = config.get(
        "odd_hour_start",
        22
    )

    odd_hour_end = config.get(
        "odd_hour_end",
        6
    )

    failed_logins = {}
    sudo_usage = {}
    threats = {}

    for event in events:
        user = event.get(
            "user",
            ""
        )

        event_type = event.get(
            "event",
            ""
        )

        timestamp = event.get(
            "timestamp",
            ""
        )

        if (
            not user
            or user == "unknown"
        ):
            continue

        if event_type == "Failed Login":
            failed_logins[user] = (
                failed_logins.get(
                    user,
                    0
                )
                + 1
            )

        if event_type == "Successful Login":
            try:
                time_value = (
                    timestamp.split()[2]
                )

                hour = int(
                    time_value.split(":")[0]
                )

                if (
                    hour >= odd_hour_start
                    or hour < odd_hour_end
                ):
                    threats.setdefault(
                        user,
                        []
                    )

                    threats[user].append(
                        "Odd-hour login"
                    )

            except (
                IndexError,
                ValueError
            ):
                pass

        if event_type == "Privilege Usage":
            sudo_usage[user] = (
                sudo_usage.get(
                    user,
                    0
                )
                + 1
            )

    for user, count in (
        failed_logins.items()
    ):
        if count >= brute_force_threshold:
            threats.setdefault(
                user,
                []
            )

            threats[user].append(
                "Brute-force"
            )

    for user, count in sudo_usage.items():
        if count >= sudo_threshold:
            threats.setdefault(
                user,
                []
            )

            threats[user].append(
                "Excessive sudo"
            )

    return threats
