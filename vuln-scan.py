# vuln_app.py
import os
import sqlite3
import hashlib

# 1. Hardcoded secret
API_KEY = "1234567890abcdef"  

def insecure_login(user, password):
    # 2. SQL Injection (string concatenation instead of parameterized queries)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def weak_hash(password):
    # 3. Weak hash function (MD5)
    return hashlib.md5(password.encode()).hexdigest()

def run_command(cmd):
    # 4. Command Injection
    os.system(cmd)

if __name__ == "__main__":
    print("Insecure login test:", insecure_login("admin", "password"))
    print("Weak hash of 'admin':", weak_hash("admin"))
    run_command("echo Hello; rm -rf /")  # dangerous!
