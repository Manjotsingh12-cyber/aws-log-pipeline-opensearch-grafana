# 🚀 Cloud SIEM Log Pipeline (AWS + OpenSearch + Grafana)
 
[![YouTube Demo](https://img.shields.io/badge/YouTube-Demo-red?style=for-the-badge&logo=youtube)](https://youtu.be/5BYWbItx59U?si=irxC9jORYVdP9sXN)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github)](https://github.com/Manjotsingh12-cyber)
[![AWS](https://img.shields.io/badge/AWS-Cloud-orange?style=for-the-badge&logo=amazon-aws)](https://aws.amazon.com)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-Search%20%26%20Analytics-blue?style=for-the-badge)](https://opensearch.org)
[![Grafana](https://img.shields.io/badge/Grafana-Dashboards-orange?style=for-the-badge&logo=grafana)](https://grafana.com)
 
---
 
## 📺 Project Demo
 
<a href="https://youtu.be/5BYWbItx59U?si=irxC9jORYVdP9sXN" target="_blank">
  <img src="https://img.youtube.com/vi/5BYWbItx59U/maxresdefault.jpg" alt="Cloud SIEM Log Pipeline Demo" width="700"/>
</a>
> 🎥 Click the thumbnail above to watch the full project walkthrough on YouTube
 
---
 
## 📌 Overview
 
This project demonstrates an **end-to-end cloud-based SIEM log pipeline** for security monitoring and detection.
 
Logs are collected from **AWS EC2 instances**, processed using **Logstash**, stored in **S3**, re-ingested into **OpenSearch**, and visualized using **Grafana dashboards** — the same architecture used by real enterprise SOC teams at scale.
 
---
 
## 🏗️ Architecture
 
```
EC2 (auth.log)
     │
     ▼
 Fluent Bit          ← Log Collection Agent
     │
     ▼
 Logstash (1)        ← Parse, Filter, Enrich
     │
     ▼
 Amazon S3           ← Centralized Log Storage
     │
     ▼
 Logstash (2)        ← Re-ingest from S3
     │
     ▼
 OpenSearch          ← Index & Search
     │
     ▼
 Grafana             ← Real-time Dashboards & Alerts
```
 
---
 
## ⚙️ Technologies Used
 
| Component | Technology |
|---|---|
| Cloud Platform | AWS (EC2, S3, IAM, CloudTrail) |
| Log Collection | Fluent Bit |
| Log Processing | Logstash |
| Storage | Amazon S3 |
| Search & Indexing | OpenSearch |
| Visualization | Grafana |
| Log Source | Linux auth.log (SSH authentication) |
| Detection Framework | MITRE ATT&CK |
 
---
 
## 🔄 Workflow
 
```
Step 1 → Logs generated on EC2 instances (auth.log)
Step 2 → Fluent Bit agent collects and forwards logs to Logstash
Step 3 → Logstash parses, filters, and enriches log data
Step 4 → Processed logs stored in Amazon S3 for durability
Step 5 → Second Logstash pipeline re-ingests logs from S3
Step 6 → Logs indexed into OpenSearch for search and analysis
Step 7 → Grafana dashboards visualize events in real time
```
 
---
 
## 🔐 Detection Use Cases
 
### 🛡️ Brute Force Detection (T1110)
- Detect repeated failed SSH login attempts from single source
- Identify suspicious authentication behavior patterns
- Correlate failed logins followed by successful access
- Alert on threshold-based anomalies in authentication logs
### 🔍 What This Detects in auth.log
```
Failed password for invalid user admin from 192.168.1.x
Failed password for root from 10.0.0.x
Accepted password for user from 192.168.1.x   ← Success after failures = alert
```
 
---
 
## 📊 Grafana Dashboard
 
The Grafana dashboard provides:
- **Real-time authentication event monitoring**
- **Failed vs successful login ratio visualization**
- **Geographic source IP mapping**
- **Timeline of authentication attempts**
- **Anomaly detection panels**
---
 
## 🚀 Setup Guide
 
### Prerequisites
- AWS Account with EC2 and S3 access
- OpenSearch domain (AWS or self-hosted)
- Grafana instance
- Fluent Bit installed on EC2
- Logstash installed
### Step 1 — Configure Fluent Bit on EC2
```ini
[INPUT]
    Name              tail
    Path              /var/log/auth.log
    Tag               auth.logs
 
[OUTPUT]
    Name              forward
    Match             *
    Host              <logstash-host>
    Port              5044
```
 
### Step 2 — Logstash Pipeline (EC2 to S3)
```ruby
input {
  beats {
    port => 5044
  }
}
 
filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host} %{DATA:program}: %{GREEDYDATA:log_message}" }
  }
}
 
output {
  s3 {
    bucket => "your-siem-bucket"
    region => "ap-south-1"
    prefix => "logs/%{+YYYY/MM/dd}/"
    codec => "json_lines"
  }
}
```
 
### Step 3 — Logstash Pipeline (S3 to OpenSearch)
```ruby
input {
  s3 {
    bucket => "your-siem-bucket"
    region => "ap-south-1"
    prefix => "logs/"
  }
}
 
output {
  opensearch {
    hosts => ["https://<opensearch-endpoint>:443"]
    index => "siem-logs-%{+YYYY.MM.dd}"
  }
}
```
 
### Step 4 — Connect Grafana to OpenSearch
1. Go to Grafana → Configuration → Data Sources
2. Add OpenSearch as data source
3. Enter your OpenSearch endpoint
4. Import or create dashboards
---
 
## 📁 Project Structure
 
```

 
---
 
## 🎯 Skills Demonstrated
 
- ✅ AWS cloud infrastructure — EC2, S3, IAM
- ✅ Log pipeline engineering — Fluent Bit, Logstash
- ✅ Security monitoring — OpenSearch, Grafana
- ✅ SIEM concepts — log ingestion, parsing, indexing
- ✅ Threat detection — brute force, authentication anomalies
- ✅ MITRE ATT&CK mapping — T1110 Brute Force
---
 
## 👤 Author
 
**Manjot Singh**
SOC Analyst | Log Engineer | Detection Engineering
 
- 📧 mbrar9766@gmail.com
- 🔗 [LinkedIn](https://linkedin.com/in/manjot67)
- 💻 [GitHub](https://github.com/Manjotsingh12-cyber)
- 🎥 [YouTube](https://www.youtube.com/@CYBERSECURITY-c7f)
---
 
## 📺 More Projects
 
| Project | GitHub | YouTube |
|---|---|---|
| Enterprise AI-Powered SOAR Pipeline | [Link](https://github.com/Manjotsingh12-cyber/ai-soc-assistant) | [Watch](https://youtu.be/S5H78cE_JT0) |
| APT Simulation & Detection Lab | [Link](https://github.com/Manjotsingh12-cyber/SOC-Lab-APT-Simulation-Detection-and-Incident-Reporting) | [Watch](https://youtu.be/rJzGhhBEIxM) |
| Cloud SIEM Log Pipeline | This Repo | [Watch](https://youtu.be/5BYWbItx59U) |
 
---
 
⭐ **If this project helped you, please give it a star!**
 
