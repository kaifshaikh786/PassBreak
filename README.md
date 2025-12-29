# 🔐 PassBreak Ultimate v2.0  
### Complete Password Security & Auditing Suite (Terminal + Web)

PassBreak Ultimate is an **advanced, terminal-driven password security framework** written in **Python**, designed for **ethical hacking, cybersecurity education, and authorized penetration testing**.

It merges **hash identification, high-performance cracking, password intelligence, breach analysis, persistent storage, and a live web dashboard** into a single unified tool.

> ⚠️ **LEGAL & ETHICAL WARNING**  
> This tool is strictly for **educational purposes** and **authorized security assessments only**.  
> Unauthorized use against systems you do not own or have permission to test is **illegal**.

---

## 📌 Why PassBreak?

Most tools focus on **one thing**:
- Only cracking
- Only hash identification
- Only wordlists

**PassBreak does everything together**, directly from the terminal, while keeping:
- Clean CLI UX
- Persistent results
- Analytics
- Automation-ready structure

---

## 🧠 Core Capabilities

### 🔍 Hash Intelligence
- Automatic hash type detection using regex & length heuristics
- Supports:
  - MD5
  - SHA1
  - SHA256
  - SHA512
  - NTLM
  - MySQL
  - bcrypt

### ⚡ High-Performance Cracking
- Multi-threaded dictionary attacks
- Adjustable thread count
- Optimized attempt tracking
- Real-time speed calculation

### 📁 Batch Processing
- Crack **hundreds or thousands of hashes** from a file
- Clean output storage
- Resume-friendly design

### 🧠 Rainbow Table Cache
- Automatically stores cracked hashes
- Instant lookup on future runs
- Reduces redundant cracking

### 🗄️ Persistent Database (SQLite)
- Stores:
  - Hash
  - Plaintext password
  - Hash type
  - Crack method
  - Crack time
  - Timestamp
- Statistics aggregation

---

## 🔐 Password Intelligence Suite

### 💪 Password Strength Analyzer
Evaluates:
- Length
- Character diversity
- Common patterns
- Entropy indicators
- Optional breach exposure

### 🔎 HaveIBeenPwned Integration
- Uses **k-Anonymity model**
- No plaintext passwords sent
- Checks if password appeared in real breaches

### 🎲 Secure Password Generator
- Cryptographically secure (`secrets`)
- Custom length
- Ambiguous character exclusion

### 🧩 Passphrase Generator
- Human-memorable
- Strong entropy
- Inspired by Diceware concepts

---

## 🛠️ Wordlist Engineering

Generate intelligent wordlists with:
- Capitalization variants
- Leetspeak substitutions
- Numeric suffixes & prefixes
- Common password patterns

Ideal for:
- Targeted attacks
- Custom engagements
- Research & labs

---

## 🌐 Web Dashboard (Flask)

Optional real-time dashboard with:
- Total cracked hashes
- Average crack time
- Recent results
- Live tools:
  - Hash identifier
  - Password generator
  - Strength checker

Run locally, no cloud, no tracking.

---

## 🧱 Architecture Overview

```text
CLI (argparse)
   |
   |-- HashIdentifier
   |-- MultiThreadedCracker
   |-- PasswordStrength
   |-- PasswordGenerator
   |-- WordlistGenerator
   |
Database (SQLite)
   |
   |-- cracked
   |-- stats
   |-- rainbow_cache
   |
Web Layer (Flask)
