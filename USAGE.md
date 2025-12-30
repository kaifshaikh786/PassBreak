#Usage Guide — PassBreak

This document provides a complete reference for PassBreak command-line usage.

---

## Hash Identification

python3 PassBreak.py --identify <hash>

Dictionary Attack
python3 PassBreak.py --crack <hash> -w wordlist.txt -t md5 --threads 8

Batch Cracking
python3 PassBreak.py --batch hashes.txt -w wordlist.txt -t sha1 -o cracked.txt

Password Strength Check
python3 PassBreak.py --strength "MyP@ssw0rd123"

Generate Secure Password
python3 PassBreak.py --generate -l 20

Generate Passphrase
python3 PassBreak.py --passphrase --words 5

View Statistics
python3 PassBreak.py --stats

Help Menu
python3 PassBreak.py --help
