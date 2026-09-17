from threat_analyzer import analyze_threats


test_events = [
    {
        "timestamp": "Jun 10 09:00:00",
        "user": "testuser",
        "event": "Failed Login"
    },
    {
        "timestamp": "Jun 10 10:00:00",
        "user": "testuser",
        "event": "Failed Login"
    },
    {
        "timestamp": "Jun 10 11:00:00",
        "user": "testuser",
        "event": "Failed Login"
    },
    {
        "timestamp": "Jun 10 12:00:00",
        "user": "testuser",
        "event": "Failed Login"
    },
    {
        "timestamp": "Jun 10 13:00:00",
        "user": "testuser",
        "event": "Failed Login"
    }
]


threats = analyze_threats(test_events)

print("Time-Window Test Result:")
print(threats)


if "testuser" not in threats:
    print("PASS: 5 failures spread across several hours were NOT classified as brute-force.")
else:
    print("FAIL: testuser was incorrectly classified as brute-force.")
