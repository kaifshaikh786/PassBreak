# 🔐 PassBreak — Advanced Password Security Analysis Suite

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-password%20analysis-red.svg)]()

**PassBreak** is a comprehensive **password security analysis and auditing framework** designed to demonstrate real-world password weaknesses through controlled, ethical techniques.

It is built for **cybersecurity students, penetration testers, and security researchers** to understand how poor password practices and weak hashing algorithms can be exploited.

> ⚠️ **LEGAL & ETHICAL NOTICE**  
> This project is intended strictly for **educational purposes, research, and authorized testing only**.  
> Unauthorized use against systems you do not own or have permission to test is illegal.

---

## 🎯 Features

- ✅ **Hash Type Identification**
- ✅ **Dictionary-Based Password Cracking**
- ✅ **Multi-Threaded Attack Engine**
- ✅ **Batch Hash Processing**
- ✅ **Password Strength Evaluation**
- ✅ **Secure Password Generator**
- ✅ **Passphrase Generator**
- ✅ **SQLite Database Logging**
- ✅ **Crack History & Statistics**
- ✅ **Terminal-Focused Workflow**

---

## 🔍 Supported Hash Algorithms

PassBreak currently supports analysis and cracking of:

- 🔐 **MD5**
- 🔐 **SHA-1**
- 🔐 **SHA-256**
- 🔐 **SHA-512**
- 🔐 **NTLM**
- 🔐 **MySQL (basic formats)**

Hash identification is performed using **length analysis, character sets, and pattern matching**.

---

## ⚡ Cracking Capabilities

### Dictionary Attacks
- Wordlist-based cracking
- Multi-threaded execution
- Real-time progress tracking
- Crack time measurement

### Batch Processing
- Crack multiple hashes from a file
- Output results to text files
- Resume-friendly workflow

### Rainbow Cache
- Previously cracked hashes stored locally
- Automatic reuse to prevent redundant work

---

## 🔐 Password Intelligence

### Strength Analysis
- Length evaluation
- Character diversity checks
- Pattern detection
- Entropy estimation

### Secure Generation
- Cryptographically secure random passwords
- Custom length support
- Passphrase generation for usability

---

## 🗄️ Database & Analytics

PassBreak uses a **local SQLite database** to store:

- Hash values
- Plaintext passwords (once cracked)
- Hash type
- Crack method
- Time taken
- Timestamp

This enables:
- Crack history review
- Statistics generation
- Learning & reporting

---

## 🖥️ Command-Line Interface

PassBreak is designed as a **pure terminal tool**, making it ideal for:

- Kali / Parrot OS
- CTF environments
- Automation & scripting
- Security labs

No GUI dependency. No cloud services.

---

## 📂 Project Structure

```text
PassBreak/
│
├── PassBreak.py           # Main application
├── README.md              # Project overview
├── INSTALLATION.md        # Installation guide
├── USAGE.md               # CLI usage reference
├── LICENSE                # MIT License
├── requirements.txt       # Dependencies
├── .gitignore
├── examples/
│   ├── test_hashes.txt
│   └── test_wordlist.txt



---

## 📸 CLI Preview

PassBreak is designed as a **terminal-first security tool**.  
Below is the real CLI interface showing the banner and available commands.

### PassBreak Banner & Help Menu

![PassBreak CLI Preview](screenshots/passbreak-cli.png)

The CLI provides access to:
- Hash identification
- Dictionary and batch cracking
- Password strength analysis
- Secure password & passphrase generation
- Wordlist generation
- Statistics and dashboard controls

All functionality is accessible directly from the terminal.

