#!/usr/bin/env python3
"""
PassBreak Ultimate - Complete Password Security Suite
Created by: Kaif Shaikh

Features:
- Hash identification & cracking (multi-threaded)
- Rainbow table support
- HaveIBeenPwned API integration
- Web dashboard with real-time stats
- Database storage of cracked passwords
- Batch hash file processing
- Password strength analysis
- Secure password generation
- Custom wordlist generation
"""

import hashlib
import string
import itertools
import re
import secrets
import argparse
import sys
import time
import sqlite3
import json
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colorama for terminal colors
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = ''

# Flask for web dashboard
try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Requests for API calls
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class Database:
    """SQLite database for storing cracked passwords and statistics"""
    
    def __init__(self, db_path='passbreak.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Cracked passwords table
        c.execute('''
            CREATE TABLE IF NOT EXISTS cracked (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE,
                password TEXT,
                hash_type TEXT,
                crack_time REAL,
                method TEXT,
                timestamp TEXT
            )
        ''')
        
        # Statistics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_attempts INTEGER,
                successful_cracks INTEGER,
                failed_attempts INTEGER,
                avg_crack_time REAL,
                date TEXT
            )
        ''')
        
        # Rainbow table cache
        c.execute('''
            CREATE TABLE IF NOT EXISTS rainbow_cache (
                hash TEXT PRIMARY KEY,
                password TEXT,
                hash_type TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_cracked(self, hash_value, password, hash_type, crack_time, method):
        """Save cracked password to database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute('''
                INSERT OR REPLACE INTO cracked (hash, password, hash_type, crack_time, method, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (hash_value, password, hash_type, crack_time, method, datetime.now().isoformat()))
            conn.commit()
        except Exception as e:
            print(f"{Fore.RED}[-] Database error: {e}")
        finally:
            conn.close()
    
    def get_cracked(self, hash_value):
        """Check if hash is already cracked"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT password, hash_type, method FROM cracked WHERE hash = ?', (hash_value,))
        result = c.fetchone()
        conn.close()
        return result
    
    def get_statistics(self):
        """Get cracking statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Total cracks
        c.execute('SELECT COUNT(*) FROM cracked')
        total = c.fetchone()[0]
        
        # By hash type
        c.execute('SELECT hash_type, COUNT(*) FROM cracked GROUP BY hash_type')
        by_type = c.fetchall()
        
        # Average crack time
        c.execute('SELECT AVG(crack_time) FROM cracked')
        avg_time = c.fetchone()[0] or 0
        
        # Recent cracks
        c.execute('SELECT hash, password, hash_type, crack_time, method, timestamp FROM cracked ORDER BY timestamp DESC LIMIT 20')
        recent = c.fetchall()
        
        conn.close()
        
        return {
            'total': total,
            'by_type': dict(by_type),
            'avg_time': avg_time,
            'recent': recent
        }
    
    def add_to_rainbow(self, hash_value, password, hash_type):
        """Add to rainbow table cache"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute('INSERT OR IGNORE INTO rainbow_cache VALUES (?, ?, ?)', 
                     (hash_value, password, hash_type))
            conn.commit()
        except:
            pass
        finally:
            conn.close()
    
    def check_rainbow(self, hash_value):
        """Check rainbow table cache"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT password, hash_type FROM rainbow_cache WHERE hash = ?', (hash_value,))
        result = c.fetchone()
        conn.close()
        return result


class HaveIBeenPwnedChecker:
    """Check passwords against HaveIBeenPwned API"""
    
    @staticmethod
    def check_password(password):
        """Check if password has been pwned"""
        if not REQUESTS_AVAILABLE:
            return None, "requests library not available"
        
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            # Query API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # Check if hash is in response
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count), "Password has been pwned!"
                return 0, "Password not found in breaches"
            else:
                return None, "API request failed"
        except Exception as e:
            return None, f"Error: {str(e)}"
    
    @staticmethod
    def check_hash(hash_value, hash_type='sha1'):
        """Check if hash exists in HIBP"""
        # Currently HIBP only supports SHA1
        if hash_type.lower() != 'sha1':
            return None, "HIBP only supports SHA1 hashes"
        
        if not REQUESTS_AVAILABLE:
            return None, "requests library not available"
        
        prefix = hash_value[:5].upper()
        suffix = hash_value[5:].upper()
        
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count), f"Found in {count} breaches"
                return 0, "Not found in breaches"
        except Exception as e:
            return None, f"Error: {str(e)}"


class HashIdentifier:
    """Identify hash types"""
    
    HASH_PATTERNS = {
        'MD5': (r'^[a-f0-9]{32}$', 32),
        'SHA1': (r'^[a-f0-9]{40}$', 40),
        'SHA256': (r'^[a-f0-9]{64}$', 64),
        'SHA512': (r'^[a-f0-9]{128}$', 128),
        'NTLM': (r'^[a-f0-9]{32}$', 32),
        'MySQL': (r'^\*[A-F0-9]{40}$', 41),
        'bcrypt': (r'^\$2[aby]\$\d{2}\$.{53}$', None),
    }
    
    @staticmethod
    def identify(hash_string):
        """Identify hash type"""
        hash_string = hash_string.strip()
        possible = []
        
        for hash_type, (pattern, length) in HashIdentifier.HASH_PATTERNS.items():
            if re.match(pattern, hash_string, re.IGNORECASE):
                possible.append(hash_type)
        
        return possible if possible else ['Unknown']


class MultiThreadedCracker:
    """Multi-threaded password cracker"""
    
    def __init__(self, num_threads=4, db=None):
        self.num_threads = num_threads
        self.attempts = 0
        self.found = False
        self.result = None
        self.lock = threading.Lock()
        self.db = db
    
    def hash_password(self, password, hash_type='md5'):
        """Hash a password"""
        hash_type = hash_type.lower()
        
        if hash_type == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        elif hash_type == 'ntlm':
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        else:
            return None
    
    def try_password(self, password, target_hash, hash_type):
        """Try a single password"""
        if self.found:
            return None
        
        with self.lock:
            self.attempts += 1
        
        hashed = self.hash_password(password, hash_type)
        
        if hashed == target_hash.lower():
            with self.lock:
                if not self.found:
                    self.found = True
                    self.result = password
            return password
        
        return None
    
    def dictionary_attack(self, target_hash, wordlist_path, hash_type='md5', verbose=True):
        """Multi-threaded dictionary attack"""
        start_time = time.time()
        
        # Check database first
        if self.db:
            cached = self.db.get_cracked(target_hash)
            if cached:
                password, cached_type, method = cached
                if verbose:
                    print(f"{Fore.GREEN}[+] Found in database: {password}")
                    print(f"{Fore.CYAN}[*] Previously cracked using: {method}\n")
                return password
        
        # Check rainbow table
        if self.db:
            rainbow = self.db.check_rainbow(target_hash)
            if rainbow:
                password, cached_type = rainbow
                if verbose:
                    print(f"{Fore.GREEN}[+] Found in rainbow table: {password}\n")
                return password
        
        if verbose:
            print(f"\n{Fore.CYAN}[*] Multi-threaded dictionary attack")
            print(f"{Fore.CYAN}[*] Threads: {self.num_threads}")
            print(f"{Fore.CYAN}[*] Target: {target_hash}")
            print(f"{Fore.CYAN}[*] Type: {hash_type.upper()}")
            print(f"{Fore.CYAN}[*] Wordlist: {wordlist_path}\n")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                futures = []
                
                for password in passwords:
                    if self.found:
                        break
                    future = executor.submit(self.try_password, password, target_hash, hash_type)
                    futures.append(future)
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        elapsed = time.time() - start_time
                        
                        if verbose:
                            print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {result}")
                            print(f"{Fore.GREEN}[+] Attempts: {self.attempts:,}")
                            print(f"{Fore.GREEN}[+] Time: {elapsed:.2f}s")
                            print(f"{Fore.GREEN}[+] Speed: {self.attempts/elapsed:.0f} h/s\n")
                        
                        # Save to database
                        if self.db:
                            self.db.save_cracked(target_hash, result, hash_type, elapsed, 'dictionary')
                            self.db.add_to_rainbow(target_hash, result, hash_type)
                        
                        return result
                    
                    if verbose and self.attempts % 10000 == 0:
                        print(f"{Fore.YELLOW}[*] Tried {self.attempts:,} passwords...", end='\r')
            
            if verbose:
                elapsed = time.time() - start_time
                print(f"\n{Fore.RED}[-] Password not found")
                print(f"{Fore.YELLOW}[*] Attempts: {self.attempts:,}")
                print(f"{Fore.YELLOW}[*] Time: {elapsed:.2f}s\n")
            
            return None
            
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist not found: {wordlist_path}")
            return None
    
    def batch_crack(self, hash_file, wordlist, hash_type='md5', output_file='cracked.txt'):
        """Crack multiple hashes from file"""
        print(f"\n{Fore.CYAN}[*] Batch cracking mode")
        print(f"{Fore.CYAN}[*] Hash file: {hash_file}")
        print(f"{Fore.CYAN}[*] Wordlist: {wordlist}\n")
        
        # Read hashes
        try:
            with open(hash_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Hash file not found")
            return
        
        print(f"{Fore.CYAN}[*] Loaded {len(hashes)} hashes\n")
        
        cracked = []
        for i, target_hash in enumerate(hashes, 1):
            print(f"{Fore.CYAN}[*] Cracking {i}/{len(hashes)}: {target_hash[:20]}...")
            
            self.found = False
            self.result = None
            self.attempts = 0
            
            result = self.dictionary_attack(target_hash, wordlist, hash_type, verbose=False)
            
            if result:
                print(f"{Fore.GREEN}[+] Found: {result}\n")
                cracked.append(f"{target_hash}:{result}")
            else:
                print(f"{Fore.RED}[-] Not found\n")
        
        # Save results
        if cracked:
            with open(output_file, 'w') as f:
                for line in cracked:
                    f.write(line + '\n')
            
            print(f"{Fore.GREEN}[+] Cracked {len(cracked)}/{len(hashes)} hashes")
            print(f"{Fore.GREEN}[+] Saved to: {output_file}\n")


class PasswordStrength:
    """Analyze password strength"""
    
    @staticmethod
    def analyze(password, check_pwned=False):
        """Comprehensive password analysis"""
        score = 0
        feedback = []
        
        length = len(password)
        
        # Length
        if length < 8:
            feedback.append(f"{Fore.RED}[-] Too short (min 8 chars)")
        elif length < 12:
            score += 1
            feedback.append(f"{Fore.YELLOW}[!] Length OK but could be longer")
        else:
            score += 2
            feedback.append(f"{Fore.GREEN}[+] Good length")
        
        # Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        variety = sum([has_lower, has_upper, has_digit, has_special])
        
        if variety == 4:
            score += 3
            feedback.append(f"{Fore.GREEN}[+] Excellent variety")
        elif variety == 3:
            score += 2
            feedback.append(f"{Fore.YELLOW}[!] Good variety")
        elif variety == 2:
            score += 1
            feedback.append(f"{Fore.YELLOW}[!] Limited variety")
        else:
            feedback.append(f"{Fore.RED}[-] Very limited variety")
        
        # Common patterns
        common = ['123', 'abc', 'password', 'qwerty', '111', 'admin']
        for pattern in common:
            if pattern in password.lower():
                score -= 1
                feedback.append(f"{Fore.RED}[-] Common pattern: '{pattern}'")
                break
        
        # Check HaveIBeenPwned
        if check_pwned and REQUESTS_AVAILABLE:
            count, msg = HaveIBeenPwnedChecker.check_password(password)
            if count is not None:
                if count > 0:
                    score -= 2
                    feedback.append(f"{Fore.RED}[-] PWNED! Found in {count:,} breaches")
                else:
                    score += 1
                    feedback.append(f"{Fore.GREEN}[+] Not found in breaches")
        
        # Strength rating
        if score >= 5:
            strength = f"{Fore.GREEN}STRONG"
        elif score >= 3:
            strength = f"{Fore.YELLOW}MODERATE"
        else:
            strength = f"{Fore.RED}WEAK"
        
        return {
            'score': max(0, score),
            'strength': strength,
            'feedback': feedback,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special,
            'length': length
        }


class PasswordGenerator:
    """Generate secure passwords"""
    
    @staticmethod
    def generate(length=16, use_special=True, use_upper=True, 
                use_lower=True, use_digits=True, exclude_ambiguous=True):
        """Generate secure random password"""
        charset = ''
        
        if use_lower:
            charset += string.ascii_lowercase
        if use_upper:
            charset += string.ascii_uppercase
        if use_digits:
            charset += string.digits
        if use_special:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in 'il1Lo0O')
        
        return ''.join(secrets.choice(charset) for _ in range(length))
    
    @staticmethod
    def generate_passphrase(word_count=4, separator='-'):
        """Generate memorable passphrase"""
        words = [
            'correct', 'horse', 'battery', 'staple', 'dragon', 'monkey',
            'sunshine', 'rainbow', 'mountain', 'ocean', 'forest', 'river',
            'thunder', 'lightning', 'crystal', 'phoenix', 'shadow', 'silver',
            'golden', 'purple', 'tiger', 'eagle', 'falcon', 'storm'
        ]
        
        selected = [secrets.choice(words).capitalize() for _ in range(word_count)]
        return separator.join(selected) + separator + str(secrets.randbelow(100))


class WordlistGenerator:
    """Generate custom wordlists"""
    
    @staticmethod
    def generate_from_pattern(base_words, output_file, add_numbers=True,
                             capitalize=True, leet_speak=True):
        """Generate wordlist with variations"""
        wordlist = set()
        
        for word in base_words:
            wordlist.add(word)
            
            if capitalize:
                wordlist.add(word.capitalize())
                wordlist.add(word.upper())
            
            if leet_speak:
                leet = word.replace('a', '4').replace('e', '3').replace('i', '1')
                leet = leet.replace('o', '0').replace('s', '5').replace('t', '7')
                wordlist.add(leet)
            
            if add_numbers:
                for num in ['123', '1', '12', '2024', '2025', '!', '@']:
                    wordlist.add(word + str(num))
                    wordlist.add(str(num) + word)
        
        with open(output_file, 'w') as f:
            for word in sorted(wordlist):
                f.write(word + '\n')
        
        return len(wordlist)


# Flask Web Dashboard
app = Flask(__name__)
db = Database()

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PassBreak Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { color: #667eea; font-size: 3em; margin-bottom: 10px; }
        .header p { color: #666; font-size: 1.2em; }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card h3 { color: #666; margin-bottom: 10px; }
        .stat-card .number { font-size: 3em; font-weight: bold; color: #667eea; }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .section h2 { color: #667eea; margin-bottom: 20px; }
        
        .crack-item {
            padding: 15px;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .crack-hash { font-family: monospace; color: #666; font-size: 0.9em; }
        .crack-password { font-weight: bold; color: #27ae60; font-size: 1.1em; }
        .crack-meta { color: #999; font-size: 0.85em; margin-top: 5px; }
        
        .tool-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .tool-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .tool-card h3 { color: #667eea; margin-bottom: 15px; }
        .tool-card input, .tool-card button {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .tool-card button {
            background: #667eea;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: bold;
        }
        .tool-card button:hover { background: #5568d3; }
        .result {
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 PassBreak</h1>
            <p>Ultimate Password Security Suite</p>
            <p style="font-size:0.9em;color:#999;margin-top:5px">Created by Kaif Shaikh</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Cracked</h3>
                <div class="number" id="total">0</div>
            </div>
            <div class="stat-card">
                <h3>Avg Crack Time</h3>
                <div class="number" id="avgTime">0s</div>
            </div>
            <div class="stat-card">
                <h3>Success Rate</h3>
                <div class="number" id="successRate">0%</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Quick Tools</h2>
            <div class="tool-section">
                <div class="tool-card">
                    <h3>🔍 Hash Identifier</h3>
                    <input type="text" id="hashInput" placeholder="Enter hash...">
                    <button onclick="identifyHash()">Identify</button>
                    <div id="hashResult" class="result" style="display:none"></div>
                </div>
                
                <div class="tool-card">
                    <h3>🎲 Password Generator</h3>
                    <input type="number" id="pwdLength" value="16" min="8" max="64">
                    <button onclick="generatePassword()">Generate</button>
                    <div id="pwdResult" class="result" style="display:none"></div>
                </div>
                
                <div class="tool-card">
                    <h3>💪 Strength Checker</h3>
                    <input type="text" id="strengthInput" placeholder="Enter password...">
                    <button onclick="checkStrength()">Check</button>
                    <div id="strengthResult" class="result" style="display:none"></div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Recent Cracks</h2>
            <div id="recentCracks"></div>
        </div>
    </div>
    
    <script>
        function loadStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total').textContent = data.total;
                    document.getElementById('avgTime').textContent = data.avg_time.toFixed(2) + 's';
                    document.getElementById('successRate').textContent = '100%';
                    
                    let html = '';
                    data.recent.forEach(crack => {
                        html += `<div class="crack-item">
                            <div class="crack-hash">${crack[0]}</div>
                            <div class="crack-password">→ ${crack[1]}</div>
                            <div class="crack-meta">${crack[2]} | ${crack[3].toFixed(2)}s | ${crack[4]}</div>
                        </div>`;
                    });
                    document.getElementById('recentCracks').innerHTML = html || '<p style="text-align:center;color:#999">No cracks yet</p>';
                });
        }
        
        function identifyHash() {
            const hash = document.getElementById('hashInput').value;
            fetch(`/api/identify?hash=${hash}`)
                .then(r => r.json())
                .then(data => {
                    const result = document.getElementById('hashResult');
                    result.style.display = 'block';
                    result.innerHTML = `<strong>Possible types:</strong><br>${data.types.join(', ')}`;
                });
        }
        
        function generatePassword() {
            const length = document.getElementById('pwdLength').value;
            fetch(`/api/generate?length=${length}`)
                .then(r => r.json())
                .then(data => {
                    const result = document.getElementById('pwdResult');
                    result.style.display = 'block';
                    result.innerHTML = `<strong>Password:</strong> ${data.password}<br><strong>Strength:</strong> ${data.strength}`;
                });
        }
        
        function checkStrength() {
            const pwd = document.getElementById('strengthInput').value;
            fetch('/api/strength', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password: pwd})
            })
                .then(r => r.json())
                .then(data => {
                    const result = document.getElementById('strengthResult');
                    result.style.display = 'block';
                    result.innerHTML = `<strong>Score:</strong> ${data.score}/5<br><strong>Strength:</strong> ${data.strength}`;
                });
        }
        
        loadStats();
        setInterval(loadStats, 5000);
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/stats')
def api_stats():
    stats = db.get_statistics()
    return jsonify({
        'total': stats['total'],
        'avg_time': stats['avg_time'],
        'recent': [[c[0][:30]+'...', c[1], c[2], c[3], c[4], c[5]] for c in stats['recent']]
    })

@app.route('/api/identify')
def api_identify():
    hash_val = request.args.get('hash', '')
    types = HashIdentifier.identify(hash_val)
    return jsonify({'types': types})

@app.route('/api/generate')
def api_generate():
    length = int(request.args.get('length', 16))
    password = PasswordGenerator.generate(length)
    analysis = PasswordStrength.analyze(password)
    return jsonify({
        'password': password,
        'strength': analysis['strength']
    })

@app.route('/api/strength', methods=['POST'])
def api_strength():
    data = request.get_json()
    password = data.get('password', '')
    analysis = PasswordStrength.analyze(password)
    return jsonify({
        'score': analysis['score'],
        'strength': analysis['strength']
    })


def print_banner():
    """Print PassBreak banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  {Fore.RED}██████{Fore.CYAN}╗  {Fore.RED}█████{Fore.CYAN}╗ {Fore.RED}███████{Fore.CYAN}╗{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██████{Fore.CYAN}╗ {Fore.RED}███████{Fore.CYAN}╗ {Fore.RED}█████{Fore.CYAN}╗ {Fore.RED}██{Fore.CYAN}╗  {Fore.RED}██{Fore.CYAN}╗ ║
║  {Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}║ {Fore.RED}██{Fore.CYAN}╔╝ ║
║  {Fore.RED}██████{Fore.CYAN}╔╝{Fore.RED}███████{Fore.CYAN}║{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██████{Fore.CYAN}╔╝{Fore.RED}█████{Fore.CYAN}╗  {Fore.RED}███████{Fore.CYAN}║{Fore.RED}█████{Fore.CYAN}╔╝  ║
║  {Fore.RED}██{Fore.CYAN}╔═══╝ {Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}║╚════{Fore.RED}██{Fore.CYAN}║╚════{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔══╝  {Fore.RED}██{Fore.CYAN}╔══{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}╔═{Fore.RED}██{Fore.CYAN}╗  ║
║  {Fore.RED}██{Fore.CYAN}║     {Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}███████{Fore.CYAN}║{Fore.RED}███████{Fore.CYAN}║{Fore.RED}██████{Fore.CYAN}╔╝{Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║  {Fore.RED}██{Fore.CYAN}╗ ║
║  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ║
║                                                           ║
║            {Fore.YELLOW}Ultimate Password Security Suite v2.0{Fore.CYAN}            ║
║            {Fore.GREEN}Created by: Kaif Shaikh{Fore.CYAN}                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='PassBreak Ultimate - Complete Password Security Suite by Kaif Shaikh',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Hash identification
  passbreak --identify 5f4dcc3b5aa765d61d8327deb882cf99

  # Dictionary attack (multi-threaded)
  passbreak --crack 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt -t md5 --threads 8

  # Batch crack multiple hashes
  passbreak --batch hashes.txt -w rockyou.txt -t md5 -o cracked.txt

  # Check password against HaveIBeenPwned
  passbreak --pwned "MyPassword123"

  # Password strength analysis
  passbreak --strength "MyP@ssw0rd123" --check-pwned

  # Generate secure password
  passbreak --generate -l 20

  # Generate passphrase
  passbreak --passphrase --words 5

  # Generate custom wordlist
  passbreak --wordlist base.txt -o custom.txt

  # Start web dashboard
  passbreak --dashboard --port 5000

  # View cracking statistics
  passbreak --stats
        '''
    )
    
    # Main operations
    parser.add_argument('--identify', metavar='HASH', help='Identify hash type')
    parser.add_argument('--crack', metavar='HASH', help='Crack password hash')
    parser.add_argument('--batch', metavar='FILE', help='Crack multiple hashes from file')
    parser.add_argument('--pwned', metavar='PASSWORD', help='Check if password is pwned')
    parser.add_argument('--strength', metavar='PASSWORD', help='Analyze password strength')
    parser.add_argument('--generate', action='store_true', help='Generate secure password')
    parser.add_argument('--passphrase', action='store_true', help='Generate passphrase')
    parser.add_argument('--wordlist', metavar='FILE', help='Generate custom wordlist from base file')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--stats', action='store_true', help='Show cracking statistics')
    
    # Options
    parser.add_argument('-w', '--wordlist-file', metavar='FILE', help='Wordlist for cracking')
    parser.add_argument('-t', '--type', default='md5', help='Hash type (md5, sha1, sha256, etc.)')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-l', '--length', type=int, default=16, help='Password length')
    parser.add_argument('--words', type=int, default=4, help='Words in passphrase')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads')
    parser.add_argument('--port', type=int, default=5000, help='Dashboard port')
    parser.add_argument('--check-pwned', action='store_true', help='Check HaveIBeenPwned API')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('-v', '--version', action='version', version='PassBreak Ultimate v2.0 by Kaif Shaikh')
    
    args = parser.parse_args()
    
    if not args.no_banner and not args.dashboard:
        print_banner()
    
    # Hash identification
    if args.identify:
        print(f"{Fore.CYAN}[*] Analyzing hash: {args.identify}\n")
        types = HashIdentifier.identify(args.identify)
        print(f"{Fore.GREEN}[+] Possible types:")
        for t in types:
            print(f"    • {t}")
        print()
        
        # Also check if in database
        cached = db.get_cracked(args.identify)
        if cached:
            print(f"{Fore.GREEN}[+] Found in database!")
            print(f"{Fore.GREEN}    Password: {cached[0]}")
            print(f"{Fore.GREEN}    Type: {cached[1]}")
            print(f"{Fore.GREEN}    Method: {cached[2]}\n")
    
    # Password cracking
    elif args.crack:
        if not args.wordlist_file:
            print(f"{Fore.RED}[-] Please specify wordlist with -w")
            sys.exit(1)
        
        cracker = MultiThreadedCracker(num_threads=args.threads, db=db)
        cracker.dictionary_attack(args.crack, args.wordlist_file, args.type)
    
    # Batch cracking
    elif args.batch:
        if not args.wordlist_file:
            print(f"{Fore.RED}[-] Please specify wordlist with -w")
            sys.exit(1)
        
        output = args.output or 'cracked.txt'
        cracker = MultiThreadedCracker(num_threads=args.threads, db=db)
        cracker.batch_crack(args.batch, args.wordlist_file, args.type, output)
    
    # HaveIBeenPwned check
    elif args.pwned:
        print(f"{Fore.CYAN}[*] Checking HaveIBeenPwned API...\n")
        count, msg = HaveIBeenPwnedChecker.check_password(args.pwned)
        
        if count is not None:
            if count > 0:
                print(f"{Fore.RED}[!] PASSWORD COMPROMISED!")
                print(f"{Fore.RED}[!] Found in {count:,} data breaches")
                print(f"{Fore.YELLOW}[!] Change this password immediately!\n")
            else:
                print(f"{Fore.GREEN}[+] Password not found in breaches")
                print(f"{Fore.GREEN}[+] This is a good sign!\n")
        else:
            print(f"{Fore.RED}[-] {msg}\n")
    
    # Strength analysis
    elif args.strength:
        print(f"{Fore.CYAN}[*] Analyzing password...\n")
        result = PasswordStrength.analyze(args.strength, check_pwned=args.check_pwned)
        
        print(f"{Fore.CYAN}Strength: {result['strength']}")
        print(f"{Fore.CYAN}Score: {result['score']}/5\n")
        
        print(f"{Fore.CYAN}Details:")
        print(f"  Length: {result['length']}")
        print(f"  Lowercase: {'✓' if result['has_lower'] else '✗'}")
        print(f"  Uppercase: {'✓' if result['has_upper'] else '✗'}")
        print(f"  Digits: {'✓' if result['has_digit'] else '✗'}")
        print(f"  Special: {'✓' if result['has_special'] else '✗'}\n")
        
        print(f"{Fore.CYAN}Feedback:")
        for item in result['feedback']:
            print(f"  {item}")
        print()
    
    # Generate password
    elif args.generate:
        password = PasswordGenerator.generate(length=args.length)
        print(f"{Fore.GREEN}[+] Generated: {Fore.YELLOW}{password}")
        
        result = PasswordStrength.analyze(password)
        print(f"{Fore.GREEN}[+] Strength: {result['strength']}\n")
    
    # Generate passphrase
    elif args.passphrase:
        passphrase = PasswordGenerator.generate_passphrase(word_count=args.words)
        print(f"{Fore.GREEN}[+] Passphrase: {Fore.YELLOW}{passphrase}")
        
        result = PasswordStrength.analyze(passphrase)
        print(f"{Fore.GREEN}[+] Strength: {result['strength']}\n")
    
    # Generate wordlist
    elif args.wordlist:
        if not args.output:
            print(f"{Fore.RED}[-] Specify output file with -o")
            sys.exit(1)
        
        print(f"{Fore.CYAN}[*] Reading: {args.wordlist}")
        
        try:
            with open(args.wordlist, 'r') as f:
                base_words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[-] File not found")
            sys.exit(1)
        
        print(f"{Fore.CYAN}[*] Generating variations...")
        count = WordlistGenerator.generate_from_pattern(base_words, args.output)
        
        print(f"{Fore.GREEN}[+] Generated {count:,} passwords")
        print(f"{Fore.GREEN}[+] Saved to: {args.output}\n")
    
    # Statistics
    elif args.stats:
        stats = db.get_statistics()
        
        print(f"{Fore.CYAN}╔════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║        PassBreak Statistics            ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════╝\n")
        
        print(f"{Fore.GREEN}Total Cracked: {stats['total']:,}")
        print(f"{Fore.GREEN}Avg Time: {stats['avg_time']:.2f}s\n")
        
        if stats['by_type']:
            print(f"{Fore.CYAN}By Hash Type:")
            for hash_type, count in stats['by_type'].items():
                print(f"  {hash_type}: {count:,}")
            print()
        
        if stats['recent']:
            print(f"{Fore.CYAN}Recent Cracks (last 10):")
            for crack in stats['recent'][:10]:
                print(f"  {crack[0][:40]}... → {crack[1]}")
            print()
    
    # Web dashboard
    elif args.dashboard:
        if not FLASK_AVAILABLE:
            print(f"{Fore.RED}[-] Flask not installed!")
            print(f"{Fore.YELLOW}[*] Install: pip3 install flask")
            sys.exit(1)
        
        print(f"\n{Fore.CYAN}🌐 PassBreak Dashboard")
        print(f"{Fore.GREEN}📊 URL: http://localhost:{args.port}")
        print(f"{Fore.CYAN}Created by: Kaif Shaikh\n")
        
        app.run(host='0.0.0.0', port=args.port, debug=False)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
