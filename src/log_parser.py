import re


# -------------------------------------------------
# Linux Authentication Log Pattern
# -------------------------------------------------

LOG_PATTERN = re.compile(
    r'(?P<date>\w+ \d+ \d+:\d+:\d+)\s+'
    r'(?P<host>\w+)\s+'
    r'(?P<service>\w+).*?:\s+'
    r'(?P<message>.*)'
)


# -------------------------------------------------
# Username Extraction
# -------------------------------------------------

USER_PATTERN = re.compile(
    r'user (\w+)'
    r'|for (?:invalid user )?(\w+)'
    r'|^(\w+)\s*:'
)


# -------------------------------------------------
# IPv4 Address Extraction
# -------------------------------------------------

IP_PATTERN = re.compile(
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
)


def extract_ip(message):
    """
    Extract an IPv4 address from an authentication
    log message.

    Returns 'N/A' when no IP address is present.
    """

    match = IP_PATTERN.search(message)

    if match:
        return match.group(0)

    return "N/A"


def parse_logs(logs):
    """
    Convert raw Linux authentication log lines
    into structured security events.
    """

    events = []

    for line in logs:

        match = LOG_PATTERN.search(line)

        if not match:
            continue

        message = match.group("message")

        # ---------------------------------------------
        # Extract Username
        # ---------------------------------------------

        user_match = USER_PATTERN.search(message)

        if user_match:

            user = (
                user_match.group(1)
                or user_match.group(2)
                or user_match.group(3)
            )

        else:

            user = "unknown"

        # ---------------------------------------------
        # Extract Source IP Address
        # ---------------------------------------------

        source_ip = extract_ip(message)

        # ---------------------------------------------
        # Determine Event Type
        # ---------------------------------------------

        if "Failed password" in message:

            event_type = "Failed Login"

        elif "Accepted password" in message:

            event_type = "Successful Login"

        elif "sudo" in line:

            event_type = "Privilege Usage"

        else:

            event_type = "Other"

        # ---------------------------------------------
        # Create Structured Event
        # ---------------------------------------------

        events.append(
            {
                "timestamp": match.group("date"),
                "host": match.group("host"),
                "service": match.group("service"),
                "user": user,
                "source_ip": source_ip,
                "event": event_type,
                "raw": message
            }
        )

    return events


# -------------------------------------------------
# Direct Testing
# -------------------------------------------------

if __name__ == "__main__":

    sample_logs = [
        (
            "Jun 10 01:12:01 kali sshd[1001]: "
            "Failed password for invalid user attacker "
            "from 192.168.1.50 port 50500 ssh2"
        ),
        (
            "Jun 10 09:30:00 kali sshd[1002]: "
            "Accepted password for alice "
            "from 192.168.1.25 port 50501 ssh2"
        ),
        (
            "Jun 10 10:00:00 kali sudo[1003]: "
            "user : TTY=pts/0 ; PWD=/home/user ; "
            "USER=root ; COMMAND=/usr/bin/apt update"
        )
    ]

    parsed_events = parse_logs(
        sample_logs
    )

    print("Parsed Events:")

    for event in parsed_events:

        print()

        print(
            f"Timestamp : {event['timestamp']}"
        )

        print(
            f"User      : {event['user']}"
        )

        print(
            f"Event     : {event['event']}"
        )

        print(
            f"Source IP : {event['source_ip']}"
        )
