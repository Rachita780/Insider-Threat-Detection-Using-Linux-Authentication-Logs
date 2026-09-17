def calculate_risk(threats):
    scores = {}

    for user, issues in threats.items():
        score = 0
        for i in issues:
            if "Brute-force" in i:
                score += 50
            if "Odd-hour" in i:
                score += 30
            if "sudo" in i:
                score += 40
        scores[user] = min(score, 100)

    return scores


if __name__ == "__main__":
    from threat_analyzer import analyze_threats
    from log_collector import read_auth_log
    from log_parser import parse_logs

    scores = calculate_risk(
        analyze_threats(parse_logs(read_auth_log()))
    )

    print("Risk Scores:")
    for u, s in scores.items():
        print(u, "->", s)
