from threat_analyzer import load_config


def calculate_risk(threats):
    config = load_config()

    brute_force_weight = config.get(
        "brute_force_weight",
        50
    )

    sudo_weight = config.get(
        "sudo_weight",
        40
    )

    odd_hour_weight = config.get(
        "odd_hour_weight",
        30
    )

    unusual_ip_weight = config.get(
        "unusual_ip_weight",
        20
    )

    scores = {}

    for user, issues in threats.items():
        score = 0

        for issue in issues:
            if "Brute-force" in issue:
                score += brute_force_weight

            if "Odd-hour" in issue:
                score += odd_hour_weight

            if "sudo" in issue.lower():
                score += sudo_weight

            if "Unusual source IP" in issue:
                score += unusual_ip_weight

        scores[user] = min(
            score,
            100
        )

    return scores


if __name__ == "__main__":
    sample_threats = {
        "alice": [
            "Odd-hour login",
            "Unusual source IP"
        ],
        "admin": [
            "Brute-force"
        ],
        "user": [
            "Excessive sudo usage"
        ]
    }

    print(
        calculate_risk(
            sample_threats
        )
    )
