
# SOC Analyst Home Lab

A hands-on Security Operations Center learning project.

## Objectives
- Parse web access logs using Python
- Detect repeated failed login responses
- Identify traversal-like request paths
- Generate structured JSON alerts
- Document investigation and remediation

## Tech Stack
- Python
- JSON
- Windows PowerShell
- Git and GitHub
- Docker Desktop (planned lab integration)

## Run
```powershell
python .\src\log_analyzer.py
```

## Project Status
Phase 1: Synthetic log analysis and basic detection rules.

## Data Disclaimer
The included events are synthetic training data.
No production logs or real user information are included.

## Limitations
These rules identify suspicious indicators, not confirmed attacks.
Further investigation and contextual validation are required.
