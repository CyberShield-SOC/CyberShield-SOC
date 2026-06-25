# CyberShield SOC

AI-Powered Log Monitoring and Threat Detection Platform

## Sprint 1 Scope
This Sprint 1 prototype focuses on log ingestion and parsing. The parser reads raw authentication/security log entries and converts them into structured records for future threat detection, alert generation, and dashboard visualization.

## Sprint 1 Deliverables Included
- Python parser script (`parser/log_parser.py`)
- Sample security log dataset (`sample_logs/auth.log`)
- Parsed JSON output (`output/parsed_logs.json`)
- Parsed CSV output (`output/parsed_logs.csv`)
- Setup documentation
- Parser design documentation
- GitHub submission guide
- Kapil Khanal contribution report
- Sprint 1 deliverables summary

## Run the Parser
```bash
python parser/log_parser.py sample_logs/auth.log
```

## Output
The parser generates:
- `output/parsed_logs.json`
- `output/parsed_logs.csv`

## Folder Structure
- `parser/` – parser source code
- `sample_logs/` – test input logs
- `output/` – generated parsed files
- `docs/` – Sprint 1 documentation
