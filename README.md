# 🚀 Cloud SIEM Log Pipeline (AWS + OpenSearch + Grafana)

[![YouTube Demo](https://img.shields.io/badge/YouTube-Watch%20Demo-red?style=for-the-badge&logo=youtube)](https://youtu.be/5BYWbItx59U?si=irxC9jORYVdP9sXN)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github)](https://github.com/Manjotsingh12-cyber)

---



---

## 📌 Overview

End-to-end cloud-based SIEM log pipeline built on AWS.

Two EC2 instances run Apache web servers with Fluent Bit collecting Apache access logs and system auth logs. Logs are forwarded to a dedicated Logstash EC2, stored in S3, re-ingested by a second Logstash pipeline, indexed into a self-hosted OpenSearch instance, and visualized through Grafana dashboards for security monitoring and threat detection.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│        EC2 Instance 1 & EC2 Instance 2      │
│  Apache Web Server                          │
│  Logs: access.log, error.log, auth.log      │
│  Agent: Fluent Bit                          │
└──────────────────┬──────────────────────────┘
                   │ Forward logs
                   ▼
┌─────────────────────────────────────────────┐
│           EC2 Instance 3                    │
│  Logstash — Parse, Filter, Enrich           │
└──────────────────┬──────────────────────────┘
                   │ Output
                   ▼
┌─────────────────────────────────────────────┐
│           Amazon S3                         │
│  Centralized Log Storage                    │
└──────────────────┬──────────────────────────┘
                   │ Re-ingest
                   ▼
┌─────────────────────────────────────────────┐
│  Logstash — S3 to OpenSearch Pipeline       │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  OpenSearch (Self-Hosted)                   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Grafana — Dashboards & Security Analysis   │
└─────────────────────────────────────────────┘
```

---

## ⚙️ Technologies Used

| Component | Technology |
|---|---|
| Cloud | AWS (EC2, S3, IAM) |
| Web Server | Apache HTTP Server |
| Log Collection | Fluent Bit |
| Log Processing | Logstash |
| Storage | Amazon S3 |
| Search & Indexing | OpenSearch (Self-Hosted) |
| Visualization | Grafana |
| Log Sources | Apache access.log, error.log, auth.log |

---

## 🔄 Workflow

```
1. Apache running on EC2-1 and EC2-2 generating access and error logs
2. Linux auth.log collected alongside Apache logs on both instances
3. Fluent Bit agents forward all logs to Logstash EC2
4. Logstash parses, filters, and enriches incoming log data
5. Logstash outputs processed logs to Amazon S3
6. Second Logstash pipeline reads logs from S3
7. Logs forwarded to self-hosted OpenSearch for indexing
8. Grafana connects to OpenSearch and visualizes dashboards
```

---

## 📄 Configuration Files

### Fluent Bit — EC2-1 & EC2-2 (`fluent-bit.conf`)

```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info

[INPUT]
    Name              tail
    Path              /var/log/apache2/access.log
    Tag               apache.access
    Parser            apache

[INPUT]
    Name              tail
    Path              /var/log/apache2/error.log
    Tag               apache.error

[INPUT]
    Name              tail
    Path              /var/log/auth.log
    Tag               auth.logs

[OUTPUT]
    Name              forward
    Match             *
    Host              <logstash-ec2-private-ip>
    Port              5044
```

---

### Fluent Bit Parser (`parsers.conf`)

```ini
[PARSER]
    Name        apache
    Format      regex
    Regex       ^(?<host>[^ ]*) [^ ]* (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)
    Time_Key    time
    Time_Format %d/%b/%Y:%H:%M:%S %z
```

---

### Logstash Pipeline 1 — Ingest to S3 (`logstash-to-s3.conf`)

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [tags] =~ "apache.access" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    mutate {
      add_field => { "log_type" => "apache_access" }
    }
  }

  if [tags] =~ "auth.logs" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{DATA:program}: %{GREEDYDATA:log_message}" }
    }
    mutate {
      add_field => { "log_type" => "auth" }
    }
  }
}

output {
  s3 {
    bucket            => "your-siem-logs-bucket"
    region            => "ap-south-1"
    prefix            => "logs/%{log_type}/%{+YYYY/MM/dd}/"
    time_file         => 5
    codec             => "json_lines"
    access_key_id     => "<your-access-key>"
    secret_access_key => "<your-secret-key>"
  }
}
```

---

### Logstash Pipeline 2 — S3 to OpenSearch (`s3-to-opensearch.conf`)

```ruby
input {
  s3 {
    bucket            => "your-siem-logs-bucket"
    region            => "ap-south-1"
    prefix            => "logs/"
    access_key_id     => "<your-access-key>"
    secret_access_key => "<your-secret-key>"
    interval          => 60
  }
}

filter {
  mutate {
    add_field => { "pipeline" => "s3-to-opensearch" }
  }
}

output {
  opensearch {
    hosts    => ["https://<opensearch-host>:9200"]
    index    => "siem-logs-%{+YYYY.MM.dd}"
    user     => "admin"
    password => "<your-password>"
    ssl      => true
    ssl_certificate_verification => false
  }
}
```

---

## 🔐 Detection Use Cases

### 🛡️ Brute Force SSH Detection (MITRE T1110)
Detects repeated failed SSH login attempts in auth.log:
```
Failed password for invalid user admin from 192.168.1.x port 22
Failed password for root from 10.0.0.x port 22
Accepted password for user from 192.168.1.x  ← Success after failures = suspicious
```

### 🌐 Apache Web Attack Detection (MITRE T1190)
Detects suspicious HTTP patterns in access.log:
```
HTTP 404 floods     → Directory scanning / enumeration
HTTP 500 errors     → Exploitation attempts
Unusual user agents → Automated scanners or bots
High request rates  → DDoS or brute force on web app
```

---

## 📊 Grafana Dashboards

Built dashboards covering:
- **Authentication events** — failed vs successful logins over time
- **Apache traffic analysis** — request volume, status codes, top source IPs
- **Anomaly panels** — spike detection for failed logins and 404 floods
- **Timeline view** — correlated events across both EC2 instances

---

## 📁 Project Structure

```

└── README.md
```

---

## 🎯 Skills Demonstrated

- ✅ AWS cloud infrastructure — EC2, S3, IAM
- ✅ Apache web server log management
- ✅ Log pipeline engineering — Fluent Bit, Logstash
- ✅ Self-hosted OpenSearch deployment and indexing
- ✅ Grafana dashboard creation for security monitoring
- ✅ Threat detection — brute force, web attacks, anomalies
- ✅ MITRE ATT&CK mapping — T1110, T1190

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

⭐ **Star this repo if it helped you!**
