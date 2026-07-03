# Python Log Analyzer

A Python-based log analyzer that processes simulated system logs and identifies suspicious user and network activity. The program summarizes log statistics and detects potential security incidents using predefined detection rules.

## Features

* Parses structured log files
* Generates a summary of system activity
* Detects suspicious login behavior
* Detects mass file deletion events
* Detects repeated password changes
* Tracks user and IP activity
* Identifies the most active users and IP addresses

## Log Format

Each log entry follows the format:

```text
YYYY-MM-DD HH:MM:SS|EVENT|IP_ADDRESS|USER
```

Example:

```text
2026-07-03 09:15:42|LOGIN_SUCCESS|192.168.1.10|alice
```

## Summary Generated

The analyzer reports:

* Total events processed
* Successful logins
* Failed logins
* Deleted files
* Most active user
* Most active IP address

## Security Detection Rules

The analyzer detects the following security events:

### Brute-force Attack

* 10 failed login attempts from the same IP targeting the same user within 1 minute.

### Repeated Failed Logins for a user

* 10 failed login attempts against the same user within 30 minutes.

### Repeated Failed Logins from an IP Address
* 10 failed login attempts from the same IP address within 30 minutes

### Successful Login After Multiple Failures

* Successful login following 5 failed login attempts for the same user within the previous 3 minutes.

### Multiple Accounts Targeted

* A single IP attempts to log into multiple different user accounts.

### Mass File Deletion

* 10 file deletion events performed by the same user within 5 minutes.

### Repeated Password Changes

* 3 password changes by the same user within 24 hours.

### Login from Multiple IP Addresses

* The same user successfully logs in from two different IP addresses within 1 minute.

## Concepts Demonstrated

* Object-Oriented Programming (OOP)
* Dictionaries
* Sets
* Lists
* File I/O
* Date and Time Processing (`datetime`)
* String Parsing
* Algorithm Design
* Data Analysis
* Conditional Logic

## Project Structure

```
.
├── main.py
├── sample_log.txt
├── test_logs/
└── README.md
```

The `test_logs` directory contains sample log files that can be used to verify each detection rule independently.

## Future Improvements

Possible future enhancements include:

* Command-line arguments for selecting log files
* Support for additional log formats
* CSV and JSON report export
* Interactive dashboard or graphical interface
* Configurable detection thresholds
* Additional security detection rules

## Purpose

This project was developed to practice Python programming, data structures, file processing, and basic cybersecurity concepts by building a simplified Security Information and Event Management (SIEM)-style log analyzer.
