import re

LOG_PATTERN = re.compile(
    r'(?P<date>\w+ \d+ \d+:\d+:\d+)\s+'
    r'(?P<host>\w+)\s+'
    r'(?P<service>\w+).*?:\s+'
    r'(?P<message>.*)'
)

USER_PATTERN = re.compile(r'user (\w+)|for (\w+)')


def parse_logs(logs):
    events = []

    for line in logs:
        match = LOG_PATTERN.search(line)
        if not match:
            continue

        message = match.group("message")

        user_match = USER_PATTERN.search(message)
        user = user_match.group(1) or user_match.group(2) if user_match else "unknown"

        if "Failed password" in message:
            event_type = "Failed Login"
        elif "Accepted password" in message:
            event_type = "Successful Login"
        elif "sudo" in line:
            event_type = "Privilege Usage"
        else:
            event_type = "Other"

        events.append({
            "timestamp": match.group("date"),
            "user": user,
            "event": event_type,
            "raw": message
        })

    return events


if __name__ == "__main__":
    from log_collector import read_auth_log
    parsed = parse_logs(read_auth_log())
    print(parsed)
