# SQL Injection Detection and Secure Data Storage

## Cloud Computing Internship - Task 2

A secure Flask-based API designed to protect user data against SQL injection attacks and unauthorized access.

## Features

- AES-256-GCM encryption for sensitive information
- Secure password hashing
- SQL injection detection
- Parameterized SQL queries using SQLAlchemy
- Capability-code based API authorization
- Input validation
- SQLite database
- Lightweight Flask REST API
- Cloud deployment ready

## Security Architecture

```text
Client
   |
   v
Flask REST API
   |
   v
Capability Code Authentication
   |
   v
Input Validation
   |
   v
SQL Injection Detection
   |
   v
Parameterized SQL Query
   |
   v
Database
   |
   +--> Password Hashing
   |
   +--> AES-256-GCM Encrypted Data