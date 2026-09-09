# NetSentinel — Network Traffic Analyzer

A beginner-to-intermediate cybersecurity project that analyzes network traffic from the **UNSW-NB15** intrusion detection dataset, detects suspicious IP behavior, calculates a risk score, and generates security reports in CSV and Excel formats.

This project was built in Python using **Pandas**, **NumPy**, and **OpenPyXL** as a portfolio project while learning cybersecurity and network traffic analysis.

## Features

* Load and merge multiple UNSW-NB15 dataset files automatically.
* Clean and preprocess network traffic data.
* Analyze basic dataset statistics.
* Detect suspicious IP activity within configurable time windows.
* Detect **Burst Traffic** based on connection volume.
* Detect **Port Scanning** activity.
* Detect **Network Scanning** activity.
* Detect IPs with a high attack ratio.
* Calculate a weighted **Risk Score** for each suspicious IP.
* Classify IPs into **Normal**, **Low**, **Medium**, and **High** risk levels.
* Generate human-readable security reports.
* Export analysis results to **CSV** and **formatted Excel** files.

## Risk Detection Rules

Each suspicious IP is evaluated using four security rules.

| Rule          | Description                                             | Score |
| ------------- | ------------------------------------------------------- | ----: |
| Burst Traffic | High number of connections during a time window.        |    +1 |
| Port Scan     | Connections to many different destination ports.        |    +3 |
| Network Scan  | Connections to many different destination IP addresses. |    +2 |
| Attack Heavy  | Large percentage of malicious traffic.                  |    +4 |

### Risk Levels

| Risk Score | Risk Level |
| ---------- | ---------- |
| 0          | Normal     |
| 1–2        | Low        |
| 3–5        | Medium     |
| 6+         | High       |

Each suspicious IP also includes **Risk Reasons** explaining why it received its score.

Example:

Risk Score: 8
Risk Level: High

Reasons:
- High traffic volume
- Multiple destination ports
- High attack ratio


## Project Structure

NetSentinel/
│
├── datasets/
│   ├── UNSW-NB15_1.csv
│   ├── UNSW-NB15_2.csv
│   ├── UNSW-NB15_3.csv
│   ├── UNSW-NB15_4.csv
│   ├── UNSW-NB15_features.csv
│   └── UNSW-NB15_LIST_EVENTS.csv
│
├── output/
│
├── src/
│   ├── config.py
│   ├── loader.py
│   ├── exporter.py
│   └── main.py
│
├── requirements.txt
├── .gitignore
└── README.md


## Installation

Clone the repository and install the required packages.


git clone <repository-url>
cd NetSentinel
pip install -r requirements.txt


## Usage

Run the project with:

python src/main.py


The program automatically:

1. Loads and merges the dataset files.
2. Cleans the dataset.
3. Detects suspicious IP behavior.
4. Calculates risk scores and risk levels.
5. Generates a security report.
6. Exports results into the `output/` folder.

## Output Files

The project generates two files inside the `output/` directory:

| File                     | Description                                                              |
| ------------------------ | ------------------------------------------------------------------------ |
| `security_analysis.csv`  | Complete analysis results in CSV format.                                 |
| `security_analysis.xlsx` | Formatted Excel report with filters, frozen header, and multiple sheets. |

The Excel report includes:

* **Risk Analysis** sheet
* **Dataset Analysis** sheet
* **Security Report** sheet

## Dataset Source

This project uses the **UNSW-NB15** network intrusion dataset.

**Dataset:** UNSW-NB15
**Provider:** Australian Centre for Cyber Security (ACCS), University of New South Wales.

The dataset contains both normal and malicious network traffic generated in a controlled cyber range and is commonly used for intrusion detection research.

## Version Roadmap

### Version 1 (Current)

* Network traffic analysis pipeline.
* Risk scoring system.
* Security report generation.
* CSV and Excel export.

### Version 2 (Planned)

* Telegram Bot integration for sending **security alerts** automatically whenever high-risk activity is detected.

## Technologies Used

* Python
* Pandas
* NumPy
* OpenPyXL

## Author

**Shanel Ghazanfari**

