# Security Log Analysis Dashboard

A web-based security analysis tool for analyzing PCAP files and detecting malicious activities using VirusTotal API.

## Features
- PCAP file upload and analysis
- VirusTotal IP reputation checking
- Threat level classification
- Interactive dashboard visualization
- Automated attack detection

## Setup
1. Install requirements:
```bash
pip install flask scapy requests
```

2. Set VirusTotal API key (optional):
```bash
# Windows
set VIRUSTOTAL_API_KEY=your_api_key_here

# Linux/Mac
export VIRUSTOTAL_API_KEY=your_api_key_here
```

3. Run the application:
```bash
python app.py
```

## Usage
1. Access the dashboard at http://localhost:5000
2. Upload PCAP file using the upload button
3. Click "Analyze" to process the file
4. View results in the dashboard

## Testing
1. Install test requirements:
```bash
pip install pytest pytest-cov
```

2. Run tests:
```bash
# Run all tests
python -m pytest

# Run tests with coverage report
python -m pytest --cov=.

# Run individual test files
python -m pytest tests/test_app.py
python -m pytest tests/test_analyze.py
```

3. Test endpoints manually:
- Use Postman or curl to test API endpoints
- Example curl commands:
```bash
# Test upload endpoint
curl -X POST -F "file=@test.pcap" http://localhost:5000/upload

# Test IP check endpoint
curl -X POST -H "Content-Type: application/json" -d '{"ip":"8.8.8.8"}' http://localhost:5000/check_ip
```
