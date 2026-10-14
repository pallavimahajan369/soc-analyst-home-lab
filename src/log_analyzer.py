
import re
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = ROOT / "logs" / "sample_access.log"
OUTPUT_FILE = ROOT / "reports" / "alerts.json"

# Apache-style access log parser
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)

failed_logins = Counter()
alerts = []
events_parsed = 0

if not LOG_FILE.exists():
    raise SystemExit(f"Log file not found: {LOG_FILE}")

with LOG_FILE.open(encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        match = LOG_PATTERN.search(line)

        if not match:
            print(f"[WARN] Could not parse line {line_number}")
            continue

        event = match.groupdict()
        events_parsed += 1

        ip = event["ip"]
        path = event["path"]
        status = int(event["status"])

        # Count failed login responses per source IP
        if path.split("?")[0] == "/login" and status == 401:
            failed_logins[ip] += 1

        # Basic path traversal indicator
        if ".." in path.split("?")[0].split("/"):
            alerts.append({
                "severity": "HIGH",
                "rule": "PATH_TRAVERSAL_INDICATOR",
                "source_ip": ip,
                "path": path,
                "status": status,
                "line": line_number,
                "note": "Traversal-like path detected; validate in context."
            })

# Alert on 3 or more failed login responses
for ip, count in failed_logins.items():
    if count >= 3:
        alerts.append({
            "severity": "MEDIUM",
            "rule": "REPEATED_FAILED_LOGINS",
            "source_ip": ip,
            "count": count,
            "threshold": 3,
            "note": "Investigate possible brute-force activity."
        })

result = {
    "log_source": "synthetic_training_data",
    "events_parsed": events_parsed,
    "alerts_generated": len(alerts),
    "alerts": alerts
}

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(
    json.dumps(result, indent=2),
    encoding="utf-8"
)

print(f"Events parsed: {events_parsed}")
print(f"Alerts generated: {len(alerts)}")

for alert in alerts:
    print(
        f"[{alert['severity']}] "
        f"{alert['rule']} | {alert['source_ip']}"
    )

print(f"Alert report saved to: {OUTPUT_FILE}")
