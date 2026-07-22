import grpc, sqlite3, threading, pytz, time, json, requests, logging
import os
import base64
import sys
import random, smtplib, ssl
import http.server
import socketserver
from concurrent import futures
from flask import Flask, render_template, redirect, request, url_for, jsonify, session, make_response # added session
import edr_pb2, edr_pb2_grpc
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
# --- CONFIGURATION ---
PKT = pytz.timezone('Asia/Karachi')
PENDING_COMMANDS = {}
# Stores the full text history for the terminal
SHELL_SESSIONS = {} 
LATEST_SHELL_RESULTS = {}
# Stores the current path for each agent to show in the prompt
SHELL_PROMPTS = {}
ACTIVE_SCANS = {}
SHELL_CONTEXT = {} # Tracks: { "agent_id": "BULK" or "INTERACTIVE" }
DEACTIVATION_PINS = {}
app = Flask(__name__)
# SYSTEM LOGGING (For the Dashboard Terminal)
logging.basicConfig(
    filename='manager.log', 
    level=logging.INFO, 
    format='[%(asctime)s] > %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()

# SILENCE THE NOISE: This stops Flask/Waitress from logging every web request
logging.getLogger('werkzeug').setLevel(logging.ERROR)

VT_API_KEY = "add your own key"
MISP_URL = "add your own machine url"
MISP_API_KEY = "add your own key"
#ABUSE_IPDB_KEY = "add your own key"
ABUSE_IPDB_KEY = "add your own key"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, 'server.crt')
KEY_FILE = os.path.join(BASE_DIR, 'server.key')
# Tracks results of mass commands: { "agent_id": {"status": "success/fail", "last_cmd": "dir"} }
C2_FLEET_STATUS = {}
FLEET_LOCKDOWN_ACTIVE = False
# Pre-made security scripts
SCRIPT_LIBRARY = {
    "Clear Temp": r"Remove-Item -Path $env:TEMP\* -Recurse -Force",
    "Reset Firewall": r"netsh advfirewall reset",
    "List Hidden Tasks": r"Get-ScheduledTask | Where-Object {$_.Settings.Hidden -eq $true}",
    "Check Listening Ports": r"Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess"
}
MANAGER_IP = "10.0.107.251" #old 192.168.3.129
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
def check_abuse_ip(ip):
    """
    Queries AbuseIPDB and returns the numerical confidence score.
    Includes advanced filtering to save API credits.
    """
    # --- STEP 1: FILTER PRIVATE & SYSTEM RANGES ---
    # These are internal IPs that will NEVER be in AbuseIPDB
    private_prefixes = (
        "127.",      # Localhost
        "192.168.",  # Home/Office
        "10.",       # Enterprise
        "172.16.",   # VPN/Docker
        "172.17.",
        "172.18.",
        "172.19.",
        "172.2",
        "172.3",
        "169.254.",  # No DHCP (APIPA)
        "224.",      # Multicast
        "0.0.0.0"    # Default
    )
    
    if ip.startswith(private_prefixes):
        return 0 # Skip API call, return safe
    
    # --- STEP 2: THE API CALL ---
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        # Using the Global variable ABUSE_IPDB_KEY here is correct
        headers = {
            'Accept': 'application/json', 
            'Key': ABUSE_IPDB_KEY
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        if response.status_code == 200:
            return response.json()['data']['abuseConfidenceScore']
        else:
            # If API returns 429 (Too many requests), return 0 to stay safe
            return 0
    except: 
        return 0

def init_db():
    conn = sqlite3.connect('edr.db')
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, agent TEXT, type TEXT, desc TEXT, proc TEXT, time TIMESTAMP)')
    #conn.execute('CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TIMESTAMP, status TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TIMESTAMP, status TEXT, is_isolated INTEGER DEFAULT 0)')
    #for col in [('cpu_usage', 'REAL'), ('ram_total', 'REAL'), ('disk_free', 'REAL')]:
     #   try:
      #      conn.execute(f'ALTER TABLE agents ADD COLUMN {col[0]} {col[1]} DEFAULT 0.0')
       # except sqlite3.OperationalError: 
        #    pass # Column already exists, ignore error
    new_cols = [
        ('cpu_usage', 'REAL'), ('ram_total', 'REAL'), ('disk_free', 'REAL'),
        ('mac_address', 'TEXT'), ('ad_domain', 'TEXT'), ('install_time', 'TIMESTAMP'),
        ('kernel_version', 'TEXT'), ('os_activation', 'TEXT'), ('os_install_date', 'TEXT'),
        ('owner_name', 'TEXT'), ('staff_no', 'TEXT'), ('phone_no', 'TEXT'), ('email_address', 'TEXT')
    ]
    
    for col_name, col_type in new_cols:
        try:
            # This adds the column if it's missing, or does nothing if it's already there
            conn.execute(f'ALTER TABLE agents ADD COLUMN {col_name} {col_type}')
        except: 
            pass 
    #conn.execute('''CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TIMESTAMP, status TEXT, is_isolated INTEGER DEFAULT 0, cpu_usage REAL DEFAULT 0.0, ram_total REAL DEFAULT 0.0, disk_free REAL DEFAULT 0.0)''')
    conn.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    # Set default if not exists
    conn.execute('INSERT OR IGNORE INTO config (key, value) VALUES ("shutdown_password", "ONPL@1234")')
    conn.execute('''CREATE TABLE IF NOT EXISTS agent_software_list (
    agent_id TEXT, 
    name TEXT, 
    version TEXT, 
    install_date TEXT,
    PRIMARY KEY(agent_id, name))''')
    conn.execute('CREATE TABLE IF NOT EXISTS usb_whitelist (id INTEGER PRIMARY KEY, device_id TEXT, agent_id TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS blocked_apps (id INTEGER PRIMARY KEY, process_name TEXT UNIQUE)')
    conn.execute('CREATE TABLE IF NOT EXISTS malicious_hashes (id INTEGER PRIMARY KEY, hash TEXT UNIQUE)')
    conn.execute('CREATE TABLE IF NOT EXISTS file_browser (agent_id TEXT PRIMARY KEY, path TEXT, items TEXT)')
    conn.execute('''CREATE TABLE IF NOT EXISTS agent_ports (
    agent_id TEXT, 
    protocol TEXT, 
    port INTEGER, 
    process TEXT)''')
    for col in [('pid', 'INTEGER'), ('is_blocked', 'INTEGER DEFAULT 0')]:
        try:
            conn.execute(f'ALTER TABLE agent_ports ADD COLUMN {col[0]} {col[1]}')
        except: 
            pass
    conn.execute('''CREATE TABLE IF NOT EXISTS cve_cache (
    software_key TEXT PRIMARY KEY, 
    cve_data TEXT, 
    last_updated TIMESTAMP)''')
    conn.execute('CREATE TABLE IF NOT EXISTS agent_compliance (agent_id TEXT PRIMARY KEY, results_json TEXT, score INTEGER)')
    # Add this inside your existing init_db() function
    conn.execute('INSERT OR IGNORE INTO config (key, value) VALUES ("fleet_scan_time", "02:00")')
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('emergency_password', 'EDR_Lock_99!')")
    conn.execute('CREATE TABLE IF NOT EXISTS scan_history (id INTEGER PRIMARY KEY, agent_id TEXT, path TEXT, total INTEGER, quarantined INTEGER, duration TEXT, status TEXT, time TIMESTAMP)')
    conn.execute('CREATE TABLE IF NOT EXISTS ip_intel (ip TEXT PRIMARY KEY, score INTEGER, description TEXT, last_checked TIMESTAMP)')
    conn.execute('CREATE TABLE IF NOT EXISTS scan_reports (id INTEGER PRIMARY KEY, agent_id TEXT, folder TEXT, total INTEGER, quarantined INTEGER, duration TEXT, seen INTEGER DEFAULT 0)')
    conn.execute('CREATE TABLE IF NOT EXISTS cve_rules (id INTEGER PRIMARY KEY, software_name TEXT, safe_version TEXT, cve_id TEXT, severity REAL)')
    conn.execute('CREATE TABLE IF NOT EXISTS agent_vulnerabilities (agent_id TEXT, cve_id TEXT, software TEXT, UNIQUE(agent_id, cve_id))')
    conn.execute("INSERT OR IGNORE INTO cve_rules (software_name, safe_version, cve_id, severity) VALUES (?, ?, ?, ?)",
                 ('Google Chrome', '120.0', 'CVE-2024-VULN-CHROME', 8.5))
    conn.execute("INSERT OR IGNORE INTO cve_rules (software_name, safe_version, cve_id, severity) VALUES (?, ?, ?, ?)",
                 ('VLC media player', '3.0.18', 'CVE-2023-4567', 5.5))
    conn.execute('CREATE TABLE IF NOT EXISTS hardware_inventory (agent_id TEXT PRIMARY KEY, data TEXT)')
    conn.execute('''CREATE TABLE IF NOT EXISTS agent_users (
    agent_id TEXT, 
    username TEXT, 
    status TEXT, 
    user_type TEXT, 
    role TEXT, 
    last_pass_change TEXT, 
    last_login TEXT, 
    history_json TEXT,
    PRIMARY KEY(agent_id, username))''')
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)')
#new behavior rule added
    conn.execute('CREATE TABLE IF NOT EXISTS behavior_rules (id INTEGER PRIMARY KEY, parent TEXT, child TEXT, agent_id TEXT)')
    # Add this inside your init_db() migration loop in manager.py
    try:
        conn.execute('ALTER TABLE alerts ADD COLUMN lineage TEXT')
        print("[+] Database Migration: Added 'lineage' column to alerts table.")
    except: pass # Column already exists
    try:
        conn.execute('ALTER TABLE alerts ADD COLUMN severity INTEGER DEFAULT 0')
    except: pass # Already exists
    conn.execute('CREATE TABLE IF NOT EXISTS two_factor (username TEXT PRIMARY KEY, code TEXT, expiry TIMESTAMP)')
    # Pre-save your credentials
    conn.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ('name', 'own password'))
    conn.commit()
    conn.close()

# --- THREAT INTELLIGENCE ---
def check_virustotal(h):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey": VT_API_KEY}, timeout=5)
        return r.json()['data']['attributes']['last_analysis_stats']['malicious'] >= 2 if r.status_code == 200 else False
    except: return False

def check_misp(h):
    try:
        headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
        body = {"value": h, "type": "sha256"}
        r = requests.post(MISP_URL, headers=headers, json=body, timeout=5, verify=False)
        return r.json().get('response', {}).get('Attribute') is not None if r.status_code == 200 else False
    except: return False
def query_nvd_for_app(app_name, app_version):
    """
    Direct Integration with NIST NVD API 2.0.
    Builds a keyword search based on app name and version.
    """
    # 1. Clean the name (NVD likes 'VLC' better than 'VLC Media Player 1.2')
    # We take the first two words of the app name for the search
    search_keyword = " ".join(app_name.split()[:2])
    
    # NIST NVD API 2.0 URL
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': f"{search_keyword} {app_version}",
        'resultsPerPage': 3 # We only take top 3 most relevant CVEs
    }

    try:
        # Note: If you have an NVD API Key, add it to headers: {"apiKey": "YOUR_KEY"}
        response = requests.get(base_url, params=params, timeout=10)
        
        if response.status_code == 200:
            cves = response.json().get('vulnerabilities', [])
            extracted_vulns = []
            
            for item in cves:
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                
                # Get Description
                desc = "No description available"
                for d in cve.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value')
                        break
                
                # Get Severity (CVSS 3.1 or 3.0)
                metrics = cve.get('metrics', {})
                cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', [{}]))
                score = cvss[0].get('cvssData', {}).get('baseScore', 0.0)
                
                extracted_vulns.append({
                    "id": cve_id,
                    "score": score,
                    "desc": desc[:200] + "..." # Truncate for DB space
                })
            return extracted_vulns
    except Exception as e:
        logger.error(f"NVD API Error for {app_name}: {e}")
    
    return []

    
def send_security_email(receiver_email, pin, agent_id):
    """Refined SMTP system to authorize EDR shutdown."""
    sender_email = "add your own email"
    password = "add your own password" 
    
    msg = MIMEMultipart()
    msg['From'] = f"EDR DEFENDER CORE <{sender_email}>"
    msg['To'] = receiver_email.strip()
    msg['Subject'] = f"CRITICAL: Authorization PIN for {agent_id}"

    body = f"""SECURITY ALERT:
    A request was made to STOP the EDR Agent on: {agent_id}.
    
    SECURE AUTHORIZATION PIN: {pin}
    
    This code is valid for 5 minutes. 
    If you did not request this, the PC may be under attack."""
    
    msg.attach(MIMEText(body, 'plain'))
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, msg['To'], msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Manager Email System Failed: {e}")
        return False
# --- HEALTH MONITOR (FIXED: DEFINED BEFORE USE) ---
def monitor_agent_health():
    while True:
        try:
            conn = sqlite3.connect('edr.db')
            limit = (datetime.now(PKT) - timedelta(seconds=90)).strftime("%Y-%m-%d %H:%M:%S")
            offline = conn.execute("SELECT id FROM agents WHERE status = 'Active' AND last_seen < ?", (limit,)).fetchall()
            for (aid,) in offline:
                conn.execute("UPDATE agents SET status = 'Inactive' WHERE id = ?", (aid,))
                conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, 'SYSTEM', 'OFFLINE: Connection Lost', 'agent.exe', ?)", 
                             (aid, datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")))
                logger.warning(f"[WARN] Agent [{aid}] connection lost (Timeout)")
            conn.commit()
            conn.close()
        #except: pass
        except Exception as e:
            logger.error(f"[ERROR] Health Monitor Failure: {e}")
        time.sleep(30)
def log_manager(msg):
    """Saves internal manager events to the database for the 'Manager Logs' view."""
    try:
        conn = sqlite3.connect('edr.db')
        now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, ?, ?, ?, ?)",
                     ('SYSTEM', 'LOG', msg, 'Manager', now))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging error: {e}")
def purge_low_score_ips():
    """Deletes cached IPs with score < 75 every 48 hours to ensure fresh data."""
    while True:
        try:
            conn = sqlite3.connect('edr.db')
            # 48 hours ago
            limit = (datetime.now(PKT) - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("DELETE FROM ip_intel WHERE score < 75 AND last_checked < ?", (limit,))
            conn.commit()
            conn.close()
            log_manager("System Maintenance: Purged expired low-score IP intelligence.")
        except: pass
        time.sleep(172800) # Wait 48 hours
# --- gRPC SERVICER ---
class EDRServicer(edr_pb2_grpc.EDRServiceServicer):
   # def handle_hb(self, aid, ip=None, os_t=None):
       # conn = sqlite3.connect('edr.db')
       # now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
       # cur = conn.execute("SELECT status FROM agents WHERE id = ?", (aid,)).fetchone()
       # if not cur or cur[0] == 'Inactive':
         #   conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, 'SYSTEM', 'ONLINE: Connected', 'agent.exe', ?)", (aid, now))
        #    logger.info(f"Agent {aid} connected.")
       # if ip and os_t and ip != "Unknown":
        #    conn.execute("INSERT OR REPLACE INTO agents (id, ip, os, last_seen, status) VALUES (?, ?, ?, ?, 'Active')", (aid, ip, os_t, now))
       # else:
        #    conn.execute("UPDATE agents SET last_seen = ?, status = 'Active' WHERE id = ?", (now, aid))
       # conn.commit(); conn.close()
   # 1. THE ASYNC WORKER (Does the slow NIST work in the background)
    def process_vulnerabilities_async(self, aid, software_list):
        conn = sqlite3.connect('edr.db')
        new_vulns_found = 0
        
        for app in software_list:
            # Check cache
            cache_key = f"{app.name}_{app.version}".lower()
            cached_res = conn.execute("SELECT cve_data FROM cve_cache WHERE software_key = ?", (cache_key,)).fetchone()
            
            vulns = []
            if cached_res:
                vulns = json.loads(cached_res[0])
            else:
                # HIT NIST NVD API
                vulns = query_nvd_for_app(app.name, app.version)
                if vulns:
                    now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute("INSERT OR REPLACE INTO cve_cache VALUES (?, ?, ?)", (cache_key, json.dumps(vulns), now))
                time.sleep(1.0) # Respect NIST limits

            for v in vulns:
                conn.execute("INSERT OR IGNORE INTO agent_vulnerabilities (agent_id, cve_id, software) VALUES (?, ?, ?)", 
                             (aid, v['id'], app.name))
                
                now_ts = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
                alert_desc = f"VULNERABILITY: {v['id']} (Score: {v['score']}) in {app.name}. {v['desc']}"
                conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, 'VULNERABILITY', ?, 'NVD_Audit', ?)",
                             (aid, alert_desc, now_ts))
                new_vulns_found += 1
            
            conn.commit() # Save after every app to be safe
        
        conn.close()
        logger.info(f"[NVD] Background Audit for {aid} complete. Found {new_vulns_found} issues.")

    # 2. THE gRPC HANDLER (Talks to the Agent)
    def PushSoftwareInventory(self, request, context):
        aid = request.agent_id
        conn = sqlite3.connect('edr.db')
        
        # Save to inventory immediately so Dashboard is updated
        conn.execute("DELETE FROM agent_software_list WHERE agent_id = ?", (aid,))
        # We also clear vulnerabilities only once at the start of a new scan
        conn.execute("DELETE FROM agent_vulnerabilities WHERE agent_id = ?", (aid,))
        
        for app in request.software:
            conn.execute("INSERT OR REPLACE INTO agent_software_list VALUES (?, ?, ?, ?)",
                         (aid, app.name, app.version, app.install_date))
        conn.commit(); conn.close()

        # --- THE FIX: Start background thread and return IMMEDIATELY ---
        # This prevents the 'Channel Closed' error on the Agent
        threading.Thread(target=self.process_vulnerabilities_async, args=(aid, list(request.software)), daemon=True).start()
        
        logger.info(f"[AUDIT] Software inventory received from {aid}. Background NIST scan started.")
        return edr_pb2.AlertResponse(received=True)
    def PushNetworkPorts(self, request, context):
        aid = request.agent_id
        conn = sqlite3.connect('edr.db')
        # Clear old ports for this agent
        conn.execute("DELETE FROM agent_ports WHERE agent_id = ?", (aid,))
        
        # Save the new list
        for p in request.ports:
            conn.execute("INSERT INTO agent_ports (agent_id, protocol, port, process, pid, is_blocked) VALUES (?, ?, ?, ?, ?, ?)",
                         (aid, p.protocol, p.port, p.process, p.pid, 1 if p.is_blocked else 0))
        
        conn.commit()
        conn.close()
        print(f"DEBUG: Stored {len(request.ports)} ports for {aid}")
        return edr_pb2.AlertResponse(received=True)
    def SendShellOutput(self, request, context):
        aid = request.agent_id
        try:
            output_text = request.output
            new_prompt = "PS C:\\>"

            # 1. SPLIT OUTPUT AND PATH (Always happens for sync)
            if "|||" in request.output:
                parts = request.output.split("|||")
                output_text = parts[0]
                new_prompt = parts[1]

            # ALWAYS update the path so navigation works in both modes
            SHELL_PROMPTS[aid] = new_prompt

            # 2. SEPARATION LOGIC: Panel vs. Terminal
            # We check the context to decide where the text goes
            ctx = SHELL_CONTEXT.get(aid, "INTERACTIVE") # Default to interactive if not set

            if ctx == "BULK":
                # --- CASE A: MASS BROADCAST ---
                # Save ONLY to the side panel cache
                LATEST_SHELL_RESULTS[aid] = output_text.strip()
                C2_FLEET_STATUS[aid] = {"status": "success", "cmd": "Broadcast Complete"}
                # Reset context back to Interactive for next time
                SHELL_CONTEXT[aid] = "INTERACTIVE"
                logger.info(f"[C2] Mass command result received for {aid} (Sent to Side Panel)")

            else:
                # --- CASE B: INTERACTIVE SHELL ---
                # Save ONLY to the long-term terminal history
                if aid not in SHELL_SESSIONS: SHELL_SESSIONS[aid] = ""
                SHELL_SESSIONS[aid] += output_text + "\n"
                logger.info(f"[SHELL] Interactive result received for {aid} (Sent to Terminal)")

        except Exception as e:
            logger.error(f"Shell Output Parse Error: {e}")
            
        return edr_pb2.AlertResponse(received=True)
    def handle_hb(self, aid, ip, os_t, cpu=0.0, ram=0.0, disk=0.0):
        conn = sqlite3.connect('edr.db')
        now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
        cur = conn.execute("SELECT status FROM agents WHERE id = ?", (aid,)).fetchone()
    
        if not cur:
            # NEW REGISTRATION
            conn.execute("INSERT INTO agents (id, ip, os, last_seen, status, cpu_usage, ram_total, disk_free) VALUES (?, ?, ?, ?, 'Active', ?, ?, ?)", 
                        (aid, ip, os_t, now, cpu, ram, disk))
            conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, 'SYSTEM', 'ONLINE: Connected', 'agent.exe', ?)", (aid, now))
            logger.info(f"[INFO] Agent [{aid}] registered from {ip}")
        elif cur[0] == 'Inactive':
            # RECONNECTION
            conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES (?, 'SYSTEM', 'ONLINE: Connected', 'agent.exe', ?)", (aid, now))
            conn.execute("UPDATE agents SET status = 'Active', last_seen = ? WHERE id = ?", (now, aid))
            logger.info(f"[INFO] Agent [{aid}] reconnected.")
        else:
            # SILENT UPDATE (No logger call here to keep terminal clean)
            conn.execute("""UPDATE agents SET last_seen = ?, ip = ?, os = ?, status = 'Active', 
                         cpu_usage = ?, ram_total = ?, disk_free = ? WHERE id = ?""", 
                         (now, ip, os_t, cpu, ram, disk, aid))
    
        conn.commit()
        conn.close()
    def SendAlert(self, r, c):
        # 1. Update heartbeat and metadata - This keeps the agent Green and IP/OS current
        self.handle_hb(r.agent_id, r.ip_address, r.os_type)
        
        # 2. Filter out STARTUP logs entirely
        if r.alert_type == "STARTUP": 
            return edr_pb2.AlertResponse(received=True)

        # Variables to be saved
        final_type = r.alert_type
        description = r.description
        if r.alert_type in ["ISOLATION", "RESTORATION"]:
            conn = sqlite3.connect('edr.db')
            # 1 if ISOLATION, 0 if RESTORATION
            state = 1 if r.alert_type == "ISOLATION" else 0
            conn.execute("UPDATE agents SET is_isolated = ? WHERE id = ?", (state, r.agent_id))
            conn.commit()
            conn.close()
            
            log_msg = "SELF-ISOLATED (Protection Active)" if state == 1 else "RESTORED (Network Open)"
            logger.warning(f"[POLICY] Agent {r.agent_id} has {log_msg}")
        # --- THE STICKY FILTER: ONLY SCORES > 75 ALLOWED ---
        if r.alert_type == "NETWORK":
            try:
                # We check if the description contains a score
                if "Abuse Score:" in r.description:
                    # Extract the number (e.g., from "Score: 11%")
                    score_val = int(r.description.split("Score: ")[1].split("%")[0])
                    
                    if score_val > 75:
                        # THREAT DETECTED: Elevate to CRITICAL (RED) and update description
                        final_type = "NETWORK_CRITICAL"
                        description = f"MALICIOUS IP BLOCKED: {r.description.split('FOUND: ')[1]} [PROCESS KILLED]"
                    else:
                        # SCORE IS 0 TO 75: Silently discard the alert (Dashboard stays clean)
                        return edr_pb2.AlertResponse(received=True)
                else:
                    # If it's a network log with no score data, ignore it
                    return edr_pb2.AlertResponse(received=True)
            except Exception:
                # If parsing fails for any reason, skip the alert
                return edr_pb2.AlertResponse(received=True)
        # ---------------------------------------------------

        # 3. Save to Database
        # This part is only reached if:
        # a) It is a NETWORK alert with score > 75
        # b) It is any other type of alert (BEHAVIOR, FILE_PROTECTION, etc.)
        conn = sqlite3.connect('edr.db')
        now_pkt = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO alerts (agent, type, desc, proc, time, lineage, severity) VALUES (?,?,?,?,?,?,?)", 
                     (r.agent_id, final_type, description, r.process_name, now_pkt, r.lineage, r.severity))
        conn.commit()
        conn.close()
        
        return edr_pb2.AlertResponse(received=True)
    def GetBehaviorRules(self, request, context):
        conn = sqlite3.connect('edr.db')
        cursor = conn.cursor()
        cursor.execute("SELECT parent, child FROM behavior_rules WHERE agent_id = ? OR agent_id = 'GLOBAL'", (request.agent_id,))
        rules = [edr_pb2.BehaviorRule(parent=row[0], child=row[1]) for row in cursor.fetchall()]
        conn.close()
        return edr_pb2.BehaviorResponse(rules=rules)
    def GetCommand(self, r, c):
        # 1. Update Heartbeat Stats
        self.handle_hb(r.agent_id, r.ip_address, r.os_type, r.cpu_usage, r.ram_total, r.disk_free)
        
        # 2. Fetch all configs
        conn = sqlite3.connect('edr.db')
        db_conf = dict(conn.execute("SELECT key, value FROM config").fetchall())
        conn.close()
        
        # 3. Assign Variables with safe defaults
        db_pass = db_conf.get("shutdown_password", "")
        scan_time = db_conf.get("fleet_scan_time", "14:00")
        emergency_p = db_conf.get("emergency_password", "EDR_Lock_99!")
        is_remediate = (db_conf.get("auto_remediate") == "ON")

        # 4. Check for Pending Commands
        cmd_data = PENDING_COMMANDS.get(r.agent_id, {"command": "NONE", "path": ""})
        
        if cmd_data["command"] != "NONE":
            PENDING_COMMANDS[r.agent_id] = {"command": "NONE", "path": ""}
            # --- FIXED RETURN 1 ---
            return edr_pb2.CommandResponse(
                command=cmd_data["command"], 
                argument=cmd_data["path"], 
                shutdown_password=db_pass, 
                daily_scan_time=scan_time, 
                remediation_active=is_remediate,
                emergency_password=emergency_p
            )
        
        # --- FIXED RETURN 2 (Must include all policy fields) ---
        return edr_pb2.CommandResponse(
            command="NONE", 
            argument="", 
            shutdown_password=db_pass, 
            daily_scan_time=scan_time,
            remediation_active=is_remediate,
            emergency_password=emergency_p
        )
    def CheckHash(self, r, c):
        h = r.hash.lower(); conn = sqlite3.connect('edr.db')
        exists = conn.execute("SELECT 1 FROM malicious_hashes WHERE hash = ?", (h,)).fetchone()
        if exists: 
            conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES ('SYSTEM', 'THREAT_INTEL', ?, 'Database', ?)", (f"Known malicious hash: {h[:12]}", datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit(); conn.close(); logger.info(f"[INFO] Threat Intelligence: Local DB match for hash {h[:12]}...")
            return edr_pb2.HashResponse(is_malicious=True)
        is_bad = check_virustotal(h) or check_misp(h)
        if is_bad:
            conn.execute("INSERT OR IGNORE INTO malicious_hashes (hash) VALUES (?)", (h,))
            conn.execute("INSERT INTO alerts (agent, type, desc, proc, time) VALUES ('SYSTEM', 'THREAT_INTEL', ?, 'VirusTotal/MISP', ?)", (f"Malicious hash detected: {h[:12]}", datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            logger.info(f"[INFO] Threat Intelligence: VT/MISP match for hash {h[:12]}...")
        conn.close(); return edr_pb2.HashResponse(is_malicious=is_bad)
    def CheckHashBatch(self, request, context):
        conn = sqlite3.connect('edr.db')
        # Efficiently check many hashes at once using SQL 'IN' clause
        placeholders = ','.join(['?'] * len(request.hashes))
        query = f"SELECT hash FROM malicious_hashes WHERE hash IN ({placeholders})"
        found = conn.execute(query, [h.lower() for h in request.hashes]).fetchall()
        conn.close()
        # Return only the ones that are actually malicious
        return edr_pb2.BatchHashResponse(malicious_hashes=[r[0] for r in found])

    def GetIPScore(self, request, context):
        ip = request.ip
        conn = sqlite3.connect('edr.db')
        try:
            # 1. Check Local Cache first
            cached = conn.execute("SELECT score, description FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
            if cached:
                conn.close()
                return edr_pb2.IPResponse(score=cached[0], description=cached[1])

            # 2. If NOT in cache, query AbuseIPDB
            score = check_abuse_ip(ip)
            desc = "Safe IP" if score == 0 else "Global Threat Intel Match"
            
            # --- THE CRITICAL FIX ---
            # Save EVERYTHING to the database (even score 0) 
            # so we never hit the API for this IP again.
            now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("INSERT OR REPLACE INTO ip_intel (ip, score, description, last_checked) VALUES (?, ?, ?, ?)",
                         (ip, score, desc, now))
            conn.commit()
            # ------------------------
            
            conn.close()
            return edr_pb2.IPResponse(score=score, description=desc)
        except Exception as e:
            if conn: conn.close()
            return edr_pb2.IPResponse(score=0, description="Error")
    def GetBlockList(self, r, c):
        conn = sqlite3.connect('edr.db')
        apps = [row[0] for row in conn.execute("SELECT process_name FROM blocked_apps").fetchall()]
        conn.close(); return edr_pb2.BlockResponse(processes=apps)

    def GetUSBPolicy(self, r, c):
        conn = sqlite3.connect('edr.db')
        ids = [row[0] for row in conn.execute("SELECT device_id FROM usb_whitelist WHERE agent_id = ? OR agent_id = 'GLOBAL'", (r.agent_id,)).fetchall()]
        conn.close(); return edr_pb2.USBResponse(allowed_device_ids=ids)

    def PushFileListing(self, r, c):
        conn = sqlite3.connect('edr.db')
        items = json.dumps([{"name": i.name, "is_dir": i.is_dir} for i in r.items])
        conn.execute("INSERT OR REPLACE INTO file_browser (agent_id, path, items) VALUES (?, ?, ?)", (r.agent_id, r.path, items))
        conn.commit(); conn.close(); return edr_pb2.AlertResponse(received=True)

    def SendScanProgress(self, request, context):
        aid = request.agent_id
        stype = request.scan_type if request.scan_type else "MANUAL"
        
        if aid not in ACTIVE_SCANS: ACTIVE_SCANS[aid] = {}
        
        ACTIVE_SCANS[aid][stype] = {
            "percent": request.percentage, 
            "path": request.current_folder,
            "last_seen": time.time()
        }
        return edr_pb2.AlertResponse(received=True) 

    #def SendScanReport(self, r, c):
     #   conn = sqlite3.connect('edr.db')
      #  now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
       # status = "SCAN COMPLETED" if r.total_files > 0 else "SCAN FAILED"
        
        ## 1. Save for the popup (Temporary)
        #conn.execute("INSERT INTO scan_reports (agent_id, folder, total, quarantined, duration) VALUES (?, ?, ?, ?, ?)", 
         #            (r.agent_id, r.folder_path, r.total_files, r.quarantined_files, r.duration))
        
        ## 2. Save for the history table (Permanent)
        #conn.execute("INSERT INTO scan_history (agent_id, path, total, quarantined, duration, status, time) VALUES (?,?,?,?,?,?,?)",
         #            (r.agent_id, r.folder_path, r.total_files, r.quarantined_files, r.duration, status, now))
        
        #conn.commit(); conn.close()
        #logger.info(f"[INFO] Scan Complete on [{r.agent_id}]. Path: {r.folder_path} | Checked: {r.total_files} | Quarantined: {r.quarantined_files}")
        #return edr_pb2.AlertResponse(received=True)
    def SendScanReport(self, request, context):
        aid = request.agent_id
        try:
            conn = sqlite3.connect('edr.db')
            now_pkt = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
            
            # Use 'request' everywhere (The FIX for the crash)
            stype = request.scan_type if request.scan_type else "MANUAL"
            base_status = "COMPLETED" if request.total_files > 0 else "FAILED"
            status = f"{stype} {base_status}"

            query = """INSERT INTO scan_history (agent_id, path, total, quarantined, duration, status, time) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)"""
            conn.execute(query, (aid, request.folder_path, request.total_files, request.quarantined_files, request.duration, status, now_pkt))
            
            conn.execute("INSERT INTO scan_reports (agent_id, folder, total, quarantined, duration) VALUES (?, ?, ?, ?, ?)", 
                         (aid, request.folder_path, request.total_files, request.quarantined_files, request.duration))
            
            conn.commit(); conn.close()
            print(f"[+] REPORT SAVED: {aid} ({stype})")
        except Exception as e:
            print(f"[-] DB ERROR in SendScanReport: {e}")
        return edr_pb2.AlertResponse(received=True)
    def PushAgentMetadata(self, r, c):
        conn = sqlite3.connect('edr.db')
        conn.execute("""UPDATE agents SET mac_address = ?, ad_domain = ?, 
                     kernel_version = ?, os_activation = ?, os_install_date = ? 
                     WHERE id = ?""", 
                     (r.mac_address, r.ad_domain, r.kernel_version, r.os_activation, r.os_install_date, r.agent_id))
        conn.commit(); conn.close()
        return edr_pb2.AlertResponse(received=True)
    def PushHardwareInventory(self, r, c):
        conn = sqlite3.connect('edr.db')
        conn.execute("INSERT OR REPLACE INTO hardware_inventory (agent_id, data) VALUES (?, ?)", (r.agent_id, r.hardware_json))
        conn.commit(); conn.close()
        return edr_pb2.AlertResponse(received=True)
    def PushUserInventory(self, request, context):
        aid = request.agent_id
        conn = sqlite3.connect('edr.db')
        # CRITICAL: Strip any spaces from the ID to ensure matching
        clean_aid = aid.strip()
        conn.execute("DELETE FROM agent_users WHERE agent_id = ?", (clean_aid,))
        
        for u in request.users:
            conn.execute("""INSERT INTO agent_users (agent_id, username, status, user_type, role, last_pass_change, last_login, history_json) 
                         VALUES (?,?,?,?,?,?,?,?)""",
                         (clean_aid, u.username, u.status, u.user_type, u.role, 
                          u.last_pass_change, u.last_login, u.login_history_json))
        conn.commit(); conn.close()
        return edr_pb2.AlertResponse(received=True)
    def PushCisBenchmark(self, request, context):
        conn = sqlite3.connect('edr.db')
        results = json.dumps([{"name": i.name, "passed": i.passed, "details": i.details} for i in request.results])
        conn.execute("INSERT OR REPLACE INTO agent_compliance VALUES (?, ?, ?)", (request.agent_id, results, request.score))
        conn.commit(); conn.close()
        return edr_pb2.AlertResponse(received=True)
# --- FLASK WEB SERVER ---
app = Flask(__name__)
app.secret_key = "EDR_DEFENDER_SECURE_KEY_99" # Secret key for login sessions

logging.basicConfig(filename='manager.log', level=logging.INFO, format='[%(asctime)s] > %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
#new thing added
@app.route('/')
def home():
    #shutdown_pwd = conn.execute("SELECT value FROM config WHERE key = 'shutdown_password'").fetchone()[0]
    # 1. INITIALIZE DEFAULTS (Prevents 500 Error on initial load)
    chart_data = {"endpoints": {"labels": [], "counts": []}, "threats": {"labels": [], "counts": []}, "history": {"labels": [], "counts": []}}
    version = "1.5.0"
    a_logs = []
    browser_data = None
    intel = [] # ADDED: Prevents error if view is not 'ip_intel'
    shutdown_pwd = "Not Set"
    avg_comp = 0.0
    non_comp_nodes = 0
    hardened_nodes = 0
    semi_hardened_nodes = 0
    scan_history = []
    software_inventory = []
    host = None
    hw_data = None
    user_list = []
    hash_list = []
    port_list = []
    cis_data = None
    sev_counts = {"info": 0, "low": 0, "med": 0, "high": 0}
    selected_user_history = None
    target_user = request.args.get('user_name')
    tab = request.args.get('tab', 'basic')
    fleet_results = C2_FLEET_STATUS
    c2_scripts = SCRIPT_LIBRARY
    fleet_lockdown = FLEET_LOCKDOWN_ACTIVE
    # Initialize shell variables for the template
    current_shell_history = ""
    current_shell_prompt = "PS C:\\>"
    # PROTECTION: If not logged in, send to login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # 2. GET REQUEST ARGUMENTS
    view = request.args.get('view', 'alerts')
    search = request.args.get('search', '')
    time_filter = request.args.get('time', 'all') # Renamed to match HTML variable
    log_agent = request.args.get('log_agent')
    b_agent = request.args.get('browsing_agent')
    # --- CRITICAL FIX: GET shell_agent FROM URL ---
    shell_agent = request.args.get('shell_agent') 
    
    if shell_agent:
        current_shell_history = SHELL_SESSIONS.get(shell_agent, "EDR Interactive Terminal Initialized...\n")
        current_shell_prompt = SHELL_PROMPTS.get(shell_agent, "PS C:\\>")
    conn = sqlite3.connect('edr.db')
    configs = dict(conn.execute("SELECT key, value FROM config").fetchall())
    #res = conn.execute("SELECT value FROM config WHERE key = 'shutdown_password'").fetchone()
    shutdown_pwd = configs.get("shutdown_password", "ONPL@1234")
    fleet_scan_time = configs.get("fleet_scan_time", "14:00")
    emergency_pwd = configs.get("emergency_password", "EDR_Lock_99!")
    #res_em = conn.execute("SELECT value FROM config WHERE key = 'emergency_password'").fetchone()
    auto_remediate_status = configs.get("auto_remediate", "OFF")
    #emergency_pwd = res_em[0] if res_em else "EDR_Lock_99!"
    #shutdown_pwd = res[0] if res else "ONPL@1234"
    # 3. FIX: DETECT DOWN AGENTS (Ensures the 'Down' block works)
    limit_ts = (datetime.now(PKT) - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE agents SET status = 'Inactive' WHERE last_seen < ?", (limit_ts,))
    conn.commit()

    # 4. ALERTS QUERY WITH TIME SLOTS
    query = "SELECT * FROM alerts WHERE (agent LIKE ? OR type LIKE ? OR proc LIKE ?)"
    params = [f'%{search}%', f'%{search}%', f'%{search}%']
    now = datetime.now(PKT)
    if time_filter == '5m': query += " AND time >= ?"; params.append((now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"))
    elif time_filter == '10m': query += " AND time >= ?"; params.append((now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"))
    elif time_filter == '1h': query += " AND time >= ?"; params.append((now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"))
    elif time_filter == '24h': query += " AND time >= ?"; params.append((now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"))
    elif time_filter == '7d': query += " AND time >= ?"; params.append((now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"))
    
    alerts = conn.execute(query + " ORDER BY id DESC LIMIT 1000", params).fetchall()
    sev_counts["info"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity <= 1").fetchone()[0]
    sev_counts["low"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity >= 2 AND severity <= 5").fetchone()[0]
    sev_counts["med"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity > 5 AND severity <= 7").fetchone()[0]
    sev_counts["high"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity > 7").fetchone()[0]
    # 5. FETCH SYSTEM DATA
    #agents = conn.execute("""
     #   SELECT a.id, a.ip, a.os, a.last_seen, a.status, a.is_isolated, 
      #         IFNULL(a.cpu_usage, 0.0), IFNULL(a.ram_total, 0.0), IFNULL(a.disk_free, 0.0),
       #        (SELECT COUNT(*) FROM agent_vulnerabilities WHERE agent_id = a.id) as v_count
        #FROM agents a""").fetchall()
    agents = conn.execute("""
        SELECT a.id, a.ip, a.os, a.last_seen, a.status, a.is_isolated, 
               ROUND(IFNULL(a.cpu_usage, 0.0), 1), 
               ROUND(IFNULL(a.ram_total, 0.0), 1), 
               ROUND(IFNULL(a.disk_free, 0.0), 1),
               (SELECT COUNT(*) FROM agent_vulnerabilities WHERE agent_id = a.id) as v_count,
               a.mac_address, a.ad_domain, a.kernel_version, a.os_activation, a.os_install_date,
               a.owner_name, a.staff_no, a.phone_no, a.email_address
        FROM agents a ORDER BY a.id ASC""").fetchall()
    if view == 'agent_details':
        aid = request.args.get('agent_id', '')
        # 1. Fuzzy match the host
        host = next((a for a in agents if a[0].strip().lower() == aid.strip().lower()), None)
        
        if host:
            # 2. Fetch Hardware
            hw_row = conn.execute("SELECT data FROM hardware_inventory WHERE agent_id LIKE ?", (aid.strip(),)).fetchone()
            if hw_row: hw_data = json.loads(hw_row[0])
            
            # 3. Fetch Users
            if tab == 'users':
                user_list = conn.execute("""
                SELECT username, status, user_type, role, last_pass_change 
                FROM agent_users 
                WHERE LOWER(agent_id) = LOWER(?)""", (aid.strip(),)).fetchall()
            # This will print in your Ubuntu terminal so you can see if the fetch worked
                print(f"DEBUG: Found {len(user_list)} human users for dashboard display.")
            
            # 4. THE FIX: Move history fetch INSIDE the host block
            if tab == 'history' and target_user:
                res = conn.execute("""
                    SELECT history_json FROM agent_users 
                    WHERE LOWER(TRIM(agent_id)) = LOWER(TRIM(?)) 
                    AND username = ?""", (aid, target_user)).fetchone()
                if res:
                    selected_user_history = json.loads(res[0])
                    
            if tab == 'software':
                # These lines are now properly indented
                software_inventory = conn.execute("""
                    SELECT name, version, install_date 
                    FROM agent_software_list 
                    WHERE agent_id LIKE ? 
                    ORDER BY name ASC""", (aid.strip(),)).fetchall()
                print(f"DEBUG: Found {len(software_inventory)} apps for {aid}")
            if tab == 'ports':
               port_list = conn.execute("SELECT protocol, port, process, pid, is_blocked FROM agent_ports WHERE agent_id LIKE ? ORDER BY port ASC", (aid.strip(),)).fetchall()
            # --- Inside 'if view == agent_details' after 'if tab == ports' ---
            if tab == 'cis':
            # We use LOWER(TRIM(?)) to match the ID exactly as we did for Users
               res = conn.execute("""
                     SELECT results_json, score 
                     FROM agent_compliance 
                     WHERE LOWER(TRIM(agent_id)) = LOWER(TRIM(?))""", (aid,)).fetchone()
            
               if res:
                # Convert the JSON string from DB back into a Python List
                  cis_data = {"results": json.loads(res[0]), "score": res[1]}
                  print(f"DEBUG: CIS Data loaded for {aid}. Score: {res[1]}%")
            # --- FETCH MALICIOUS HASHES ---
            # This logic ensures that when view='hashes', the variable is filled with your 16 records
    
    #if view == 'agent_details':
     #   aid = request.args.get('agent_id', '')
      #  host = next((a for a in agents if a[0].strip().lower() == aid.strip().lower()), None)
        #host = next((a for a in agents if a[0].lower() == aid.lower()), None)
        #host = next((a for a in agents if a[0] == aid), None)
        #if aid:
         #   hw_row = conn.execute("SELECT data FROM hardware_inventory WHERE agent_id = ?", (aid,)).fetchone()
          #  if hw_row:
           #     hw_data = json.loads(hw_row[0]) # Convert string back to Python Dictionary
       # if host:
            # 2. FETCH HARDWARE: Use LIKE to prevent casing issues from hiding data
        #    hw_row = conn.execute("SELECT data FROM hardware_inventory WHERE agent_id LIKE ?", (aid.strip(),)).fetchone()
         #   if hw_row:
          #      hw_data = json.loads(hw_row[0])
        #if tab == 'users':
         #   user_list = conn.execute("""
          #  SELECT agent_id, username, status, user_type, role, 
           # last_pass_change, last_login, history_json 
            #FROM agent_users 
            #WHERE LOWER(TRIM(agent_id)) = LOWER(TRIM(?))""", (aid,)).fetchall()
            #print(f"MANAGER: Found {len(user_list)} user accounts for {aid}")

            # 4. FETCH HISTORY: Updated to use the same LOWER(TRIM) logic as users
        #if tab == 'history' and target_user:
        #    res = conn.execute("""
         #   SELECT history_json FROM agent_users 
          #  WHERE LOWER(TRIM(agent_id)) = LOWER(TRIM(?)) 
           # AND username = ?""", (aid, target_user)).fetchone()
            #if res:
             #   selected_user_history = json.loads(res[0])
        #host = conn.execute("""
         #   SELECT id, ip, os, last_seen, status, is_isolated, 
          #         cpu_usage, ram_total, disk_free, 
           #        (SELECT COUNT(*) FROM agent_vulnerabilities WHERE agent_id = agents.id),
            #       mac_address, ad_domain, kernel_version, os_activation, os_install_date,
             #      owner_name, staff_no, phone_no, email_address
            #FROM agents WHERE id = ?""", (aid,)).fetchone()
    #agents = conn.execute("SELECT * FROM agents").fetchall()
    usb = conn.execute("SELECT id, device_id, agent_id FROM usb_whitelist").fetchall()
    blocked = conn.execute("SELECT id, process_name FROM blocked_apps").fetchall()
    beh_rules = conn.execute("SELECT id, parent, child, agent_id FROM behavior_rules").fetchall()
    if view == 'hashes':
        # Open a clean cursor to fetch the data
        cursor = conn.cursor()
        hash_rows = cursor.execute("SELECT id, hash FROM malicious_hashes ORDER BY id DESC").fetchall()
        
        # Mapping the result to the hash_list variable
        hash_list = hash_rows
        
        # DEBUG: This will print in your Ubuntu Terminal. 
        # Check this to confirm Python sees the 17 rows.
        print(f"TERMINAL DEBUG: View is 'hashes'. Database returned {len(hash_list)} rows.")
    # 6. MANAGER LOGS (Real System File)
    try:
        with open('manager.log', 'r') as f:
            m_logs = f.readlines()[-50:]; m_logs.reverse()
    except: m_logs = ["No logs found."]
    
    # 7. AGENT SPECIFIC LOGS
    if log_agent:
        a_logs = conn.execute("SELECT time, type, desc FROM alerts WHERE agent = ? ORDER BY id DESC LIMIT 50", (log_agent,)).fetchall()
    # 11. GLOBAL THREAT INTEL CACHE (NEW FEATURE)
    # Fetch all IPs that were found to be malicious by AbuseIPDB
    intel = conn.execute("SELECT ip, score, description, last_checked FROM ip_intel WHERE score > 0 ORDER BY score DESC").fetchall()
    scan_history = conn.execute("SELECT time, agent_id, path, total, quarantined, duration, status FROM scan_history ORDER BY id DESC LIMIT 10").fetchall()
    # 8. CALCULATE STATS FOR THE 3 BLOCKS
    # --- POSTURE CALCULATION ENGINE ---
    # 1. Fetch every compliance score stored in the database
    score_rows = conn.execute("SELECT score FROM agent_compliance").fetchall()
    
    if score_rows:
        # Convert list of tuples to list of numbers
        all_scores = [r[0] for r in score_rows]
        
        # 2. Calculate Average (Sum of scores / Number of reporting agents)
        avg_comp = round(sum(all_scores) / len(all_scores), 1)
        
        # 3. Categorize Nodes based on Score
        hardened_nodes = len([s for s in all_scores if s >= 90])
        semi_hardened_nodes = len([s for s in all_scores if 50 <= s < 90])
        non_comp_nodes = len([s for s in all_scores if s < 50])
    else:
        # Fallback if no agents have scanned yet
        avg_comp, hardened_nodes, semi_hardened_nodes, non_comp_nodes = 0.0, 0, 0, 0
    total = len(agents)
    active = len([a for a in agents if a[4] == 'Active'])
    inactive = total - active
    
    # 9. BROWSER DATA
    if b_agent:
        res = conn.execute("SELECT path, items FROM file_browser WHERE agent_id = ?", (b_agent,)).fetchone()
        if res: browser_data = {"path": res[0], "items": json.loads(res[1])}

    # 10. EVENT DETAILS ANALYTICS
    if view == 'event_details':
        top_endpoints = conn.execute("SELECT agent, COUNT(*) as count FROM alerts WHERE type NOT IN ('SYSTEM', 'STARTUP', 'SCAN_INFO') GROUP BY agent ORDER BY count DESC LIMIT 5").fetchall()
        chart_data["endpoints"] = {"labels": [r[0] for r in top_endpoints], "counts": [r[1] for r in top_endpoints]}
        
        threat_dist = conn.execute("SELECT type, COUNT(*) as count FROM alerts WHERE type NOT IN ('SYSTEM', 'STARTUP', 'SCAN_INFO') GROUP BY type").fetchall()
        chart_data["threats"] = {"labels": [r[0] for r in threat_dist], "counts": [r[1] for r in threat_dist]}
        
        history = conn.execute("SELECT DATE(time) as d, COUNT(*) FROM alerts WHERE time >= ? AND type NOT IN ('SYSTEM', 'STARTUP') GROUP BY d ORDER BY d ASC", ((now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),)).fetchall()
        chart_data["history"] = {"labels": [r[0] for r in history], "counts": [r[1] for r in history]}
        
    conn.close()
    return render_template('index.html', **locals())
@app.route('/exec_shell', methods=['POST'])
def exec_shell():
    aid = request.form.get('agent_id')
    cmd = request.form.get('cmd')
    if aid and cmd:
        # Mark this as an Interactive command
        SHELL_CONTEXT[aid] = "INTERACTIVE"
        
        prompt = SHELL_PROMPTS.get(aid, "PS C:\\>")
        if aid not in SHELL_SESSIONS: SHELL_SESSIONS[aid] = ""
        SHELL_SESSIONS[aid] += f"{prompt} {cmd}\n"
        
        PENDING_COMMANDS[aid] = {"command": "SHELL", "path": cmd}
    return "OK"

@app.route('/api/get_shell')
def api_get_shell():
    aid = request.args.get('agent_id')
    # Return both the full history and the current prompt for the UI
    return jsonify({
        "history": SHELL_SESSIONS.get(aid, "Waiting for agent..."),
        "prompt": SHELL_PROMPTS.get(aid, "PS C:\\>")
    })
@app.template_filter('b64encode')
def b64encode_filter(s):
    if not s: return ""
    return base64.b64encode(s.encode()).decode()
@app.route('/api/dist/<filename>')
def download_file(filename):
    # This serves the uploaded files to the agents
    from flask import send_from_directory
    return send_from_directory(UPLOAD_FOLDER, filename)
@app.route('/exec_bulk', methods=['POST'])
def exec_bulk():
    global FLEET_LOCKDOWN_ACTIVE
    if not session.get('logged_in'): return "Unauthorized", 403
    agent_ids = request.form.getlist('selected_agents')
    cmd = request.form.get('cmd')
    action_type = request.form.get('action_type')
    
    final_path = ""
    
    if action_type == 'FILE_PUSH':
        file = request.files.get('local_file')
        if file and file.filename != '':
            # 1. Clean the filename (removes spaces, etc.)
            filename = secure_filename(file.filename)
            # 2. Save using the CLEAN name
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)
            
            # 3. Generate the URL using the CLEAN name
            # Note: We use port 5000 and NO path prefix because the relay root IS the uploads folder
            final_path = f"http://{MANAGER_IP}:5000/{filename}"
            log_manager(f"C2: Local file '{filename}' staged at {final_path}")
        else:
            final_path = request.form.get('file_url')
            
    conn = sqlite3.connect('edr.db')
    
    
    # Broadcast to all selected agents
    for aid in agent_ids:
        if action_type == 'ISOLATE':
            PENDING_COMMANDS[aid] = {"command": "ISOLATE", "path": ""}
            C2_FLEET_STATUS[aid] = {"status": "in_flight", "cmd": "NUCLEAR LOCKDOWN"}
            conn.execute("UPDATE agents SET is_isolated = 1 WHERE id = ?", (aid,))
            FLEET_LOCKDOWN_ACTIVE = True
            
        elif action_type == 'RESTORE':
            PENDING_COMMANDS[aid] = {"command": "RESTORE", "path": ""}
            C2_FLEET_STATUS[aid] = {"status": "in_flight", "cmd": "NUCLEAR RESTORE"}
            # SYNC: Update Database so Summary Page changes automatically
            conn.execute("UPDATE agents SET is_isolated = 0 WHERE id = ?", (aid,))
            FLEET_LOCKDOWN_ACTIVE = False
            
        elif action_type == 'FILE_PUSH':
            if final_path:
                PENDING_COMMANDS[aid] = {"command": "DOWNLOAD_RUN", "path": final_path}
                C2_FLEET_STATUS[aid] = {"status": "in_flight", "cmd": f"Deploy: {filename if 'filename' in locals() else 'URL'}"}
        else:
            SHELL_CONTEXT[aid] = "BULK" # Mark as Bulk for the Side Panel
            PENDING_COMMANDS[aid] = {"command": "SHELL", "path": cmd}
            C2_FLEET_STATUS[aid] = {"status": "in_flight", "cmd": cmd}
    conn.commit()
    conn.close()
    
    #log_manager(f"C2 MASS ACTION: {action_type} sent to {len(agent_ids)} agents.")
    logger.info(f"[INFO] Admin initiated {action_type} on {len(agent_ids)} agents.")
    return redirect("/?view=c2")
@app.route('/api/get_bulk_results')
def api_get_bulk_results():
    if not session.get('logged_in'): return jsonify({})
    # Simply return the dictionary of latest outputs
    return jsonify(LATEST_SHELL_RESULTS)
@app.route('/api/scan_status')
def scan_status():
    # Only return MANUAL scans in a flat format for the main progress bar
    manual_scans = {}
    for aid, types in ACTIVE_SCANS.items():
        if "MANUAL" in types: manual_scans[aid] = types["MANUAL"]
    return jsonify(manual_scans)
@app.route('/toggle_rule/<rule_name>/<status>')
def toggle_rule(rule_name, status):
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    conn = sqlite3.connect('edr.db')
    # Update the config table (e.g., set auto_remediate to 'ON')
    conn.execute("UPDATE config SET value = ? WHERE key = ?", (status.upper(), rule_name))
    conn.commit()
    conn.close()
    
    log_manager(f"POLICY CHANGE: {rule_name} is now {status.upper()}")
    # Redirect back to the rules page
    return redirect(url_for('home', view='rules'))
@app.route('/api/browser_data')
def api_browser_data():
    aid = request.args.get('agent_id')
    conn = sqlite3.connect('edr.db')
    res = conn.execute("SELECT path, items FROM file_browser WHERE agent_id = ?", (aid,)).fetchone()
    conn.close()
    if res:
        # We return the path and items as a clean JSON object
        return jsonify({"path": res[0], "items": json.loads(res[1])})
    return jsonify({"path": "EMPTY", "items": []})

@app.route('/request_browse')
def request_browse():
    aid = request.args.get('agent_id')
    path = request.args.get('path', 'ROOT')
    # Force 'ROOT' to be uppercase for consistency
    if path.upper() == "ROOT": path = "ROOT"
    PENDING_COMMANDS[aid] = {"command": "DIR_LIST", "path": path}
    logger.info(f"[REMOTE] Admin browsing file system of [{aid}] at path: {path}")
    return "OK"
#@app.route('/api/browser_data')
#def api_browser_data():
 #   aid = request.args.get('agent_id'); conn = sqlite3.connect('edr.db')
  #  res = conn.execute("SELECT path, items FROM file_browser WHERE agent_id = ?", (aid,)).fetchone()
   # conn.close(); return jsonify({"path": res[0], "items": json.loads(res[1])}) if res else jsonify({"path": "", "items": []})

#@app.route('/request_browse')
#def request_browse():
 #   aid, path = request.args.get('agent_id'), request.args.get('path', 'ROOT')
  #  PENDING_COMMANDS[aid] = {"command": "DIR_LIST", "path": path}
   # return "OK"

@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    aid, path = request.form.get('agent_id'), request.form.get('scan_path')
    if aid: PENDING_COMMANDS[aid] = {"command": "SCAN", "path": path}
    logger.info(f"[ACTION] Remote Scan initiated on [{aid}] for path: {path}")
    return "OK"

@app.route('/add_block', methods=['POST'])
def add_block():
    name = request.form.get('app_name')
    if name:
        conn = sqlite3.connect('edr.db'); conn.execute("INSERT OR IGNORE INTO blocked_apps (process_name) VALUES (?)", (name.lower(),)); conn.commit(); conn.close()
    logger.info(f"[POLICY] Admin added global block rule for process: {name}")
    return redirect(url_for('home', view='policy'))

@app.route('/del_block/<int:id>')
def del_block(id):
    conn = sqlite3.connect('edr.db'); conn.execute("DELETE FROM blocked_apps WHERE id = ?", (id,)); conn.commit(); conn.close()
    return redirect(url_for('home', view='policy'))

@app.route('/update_fleet_schedule', methods=['POST'])
def update_fleet_schedule():
    new_time = request.form.get('scan_time')
    conn = sqlite3.connect('edr.db')
    conn.execute("UPDATE config SET value = ? WHERE key = 'fleet_scan_time'", (new_time,))
    conn.commit(); conn.close()
    log_manager(f"POLICY: Global Fleet Scan scheduled for {new_time} daily.")
    return redirect(url_for('home', view='active_scan'))
@app.route('/api/active_fleet_scans')
def api_active_fleet_scans():
    # Only return FLEET scans for the fleet orchestration page
    fleet_scans = {}
    now = time.time()
    for aid, types in ACTIVE_SCANS.items():
        if "FLEET" in types:
            if now - types["FLEET"]["last_seen"] < 30: # Timeout after 30s
                fleet_scans[aid] = types["FLEET"]
    return jsonify(fleet_scans)
@app.route('/add_usb', methods=['POST'])
def add_usb():
    dev, target = request.form.get('device_id'), request.form.get('target_agent')
    conn = sqlite3.connect('edr.db'); conn.execute("INSERT INTO usb_whitelist (device_id, agent_id) VALUES (?, ?)", (dev, target)); conn.commit(); conn.close()
    logger.info(f"[POLICY] Admin whitelisted USB [{request.form.get('device_id')}] for Agent [{request.form.get('target_agent')}]")
    return redirect(url_for('home', view='usb'))

@app.route('/del_usb/<int:id>')
def del_usb(id):
    conn = sqlite3.connect('edr.db'); conn.execute("DELETE FROM usb_whitelist WHERE id = ?", (id,)); conn.commit(); conn.close()
    return redirect(url_for('home', view='usb'))
@app.route('/toggle_port/<aid>/<proto>/<int:port>/<action>')
def toggle_port(aid, proto, port, action):
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    cmd = "BLOCK_PORT" if action == 'block' else "UNBLOCK_PORT"
    arg = f"{proto}:{port}" # Format: "TCP:135"
    
    PENDING_COMMANDS[aid] = {"command": cmd, "path": arg}
    
    # Update local DB immediately so UI reflects the change
    conn = sqlite3.connect('edr.db')
    status = 1 if action == 'block' else 0
    conn.execute("UPDATE agent_ports SET is_blocked = ? WHERE agent_id = ? AND port = ? AND protocol = ?", (status, aid, port, proto))
    conn.commit(); conn.close()
    
    log_manager(f"FIREWALL: {action.upper()} request sent for {aid} on {proto}/{port}")
    return redirect(url_for('home', view='agent_details', agent_id=aid, tab='ports'))
@app.route('/add_hash', methods=['POST'])
def add_hash():
    if not session.get('logged_in'): return redirect(url_for('login'))
    
    # .strip() removes any accidental spaces or newlines from copy-pasting
    h = request.form.get('file_hash', '').strip().lower()
    
    if len(h) == 64: 
        conn = sqlite3.connect('edr.db')
        conn.execute("INSERT OR IGNORE INTO malicious_hashes (hash) VALUES (?)", (h,))
        conn.commit()
        conn.close()
        log_manager(f"THREAT HUNTING: Manually blacklisted hash: {h[:12]}...")
    else:
        # This will tell you in the Ubuntu terminal if the hash was the wrong length
        print(f"ERROR: Invalid hash length received: {len(h)} characters. (Expected 64)")
        
    return redirect("/?view=hashes")

@app.route('/del_hash/<int:id>')
def del_hash(id):
    if not session.get('logged_in'): return redirect(url_for('login'))
    conn = sqlite3.connect('edr.db')
    try:
        conn.execute("DELETE FROM malicious_hashes WHERE id = ?", (id,))
        conn.commit()
    except Exception as e:
        print(f"Error deleting hash: {e}")
    finally:
        conn.close()
    return redirect("/?view=hashes") # Direct string redirect is safer
@app.route('/isolate/<aid>')
def isolate_agent_cmd(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    conn = sqlite3.connect('edr.db')
    # Update DB state to 1 (Isolated)
    conn.execute("UPDATE agents SET is_isolated = 1 WHERE id = ?", (aid,))
    conn.commit(); conn.close()
    PENDING_COMMANDS[aid] = {"command": "ISOLATE", "path": ""}
    log_manager(f"NETWORK LOCKDOWN initiated for agent: {aid}")
    return redirect("/?view=summary")

@app.route('/restore/<aid>')
def restore_agent_cmd(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    conn = sqlite3.connect('edr.db')
    # Update DB state to 0 (Restored)
    conn.execute("UPDATE agents SET is_isolated = 0 WHERE id = ?", (aid,))
    conn.commit(); conn.close()
    PENDING_COMMANDS[aid] = {"command": "RESTORE", "path": ""}
    log_manager(f"NETWORK RESTORE initiated for agent: {aid}")
    return redirect("/?view=summary")
def get_report():
    conn = sqlite3.connect('edr.db'); rep = conn.execute("SELECT id, agent_id, folder, total, quarantined, duration FROM scan_reports WHERE seen = 0").fetchone()
    if rep:
        conn.execute("UPDATE scan_reports SET seen = 1 WHERE id = ?", (rep[0],)); conn.commit(); conn.close()
        return json.dumps({"agent": rep[1], "folder": rep[2], "total": rep[3], "quar": rep[4], "time": rep[5]})
    return "{}"
# --- LOGIN ROUTES ---
@app.route('/update_settings', methods=['POST'])
def update_settings():
    if not session.get('logged_in'): 
        return redirect(url_for('login'))
    
    new_user = request.form.get('new_user')
    new_pass = request.form.get('new_pass')
    new_shutdown = request.form.get('new_shutdown')
    new_emergency = request.form.get('new_emergency')
    old_user = session.get('user')

    conn = sqlite3.connect('edr.db')
    try:
        # 1. Update Manager Credentials
        if new_user and new_pass and new_pass.strip() != "":
            conn.execute("UPDATE users SET username = ?, password = ? WHERE username = ?", (new_user, new_pass, old_user))
            session['user'] = new_user
        
        # 2. Update Global Agent Shutdown Password
        if new_shutdown:
            conn.execute("UPDATE config SET value = ? WHERE key = 'shutdown_password'", (new_shutdown,))
            log_manager(f"SECURITY: Global Shutdown Key updated by {session.get('user')}")
        
        #new_emergency = request.form.get('new_emergency')
        if new_emergency:
            conn.execute("UPDATE config SET value = ? WHERE key = 'emergency_password'", (new_emergency,))
            log_manager(f"POLICY: Brute-Force Recovery Password updated.")
        conn.commit()
    except Exception as e:
        print(f"Error updating settings: {e}")
    finally:
        conn.close()
    
    # --- THE CRITICAL FIX ---
    # Using a direct string redirect prevents the 500 Routing Error
    return redirect("/?view=settings")
@app.route('/update_agent_asset', methods=['POST'])
def update_agent_asset():
    if not session.get('logged_in'): return redirect(url_for('login'))
    aid = request.form.get('agent_id')
    conn = sqlite3.connect('edr.db')
    conn.execute("""UPDATE agents SET owner_name = ?, staff_no = ?, phone_no = ?, email_address = ? 
                 WHERE id = ?""", (request.form.get('owner'), request.form.get('staff'), 
                                   request.form.get('phone'), request.form.get('email'), aid))
    conn.commit(); conn.close()
    return redirect(url_for('home', view='agent_details', agent_id=aid))
@app.route('/request_deactivate/<aid>')
# --- Add this new route to manager.py ---
def request_deactivate(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    # Generate 6-digit PIN
    pin = str(random.randint(100000, 999999))
    DEACTIVATION_PINS[aid] = {"pin": pin, "expiry": time.time() + 300}
    
    # Send to YOUR email
    if send_security_email("own email", pin, aid):
        log_manager(f"SHIELD: Deactivation PIN generated and emailed for {aid}")
        return redirect(url_for('home', view='summary', deact_pending=aid))
    else:
        return "Email System Error. Check Manager Logs.", 500

@app.route('/confirm_deactivate', methods=['POST'])
def confirm_deactivate():
    aid = request.form.get('agent_id')
    user_pin = request.form.get('pin')
    
    record = DEACTIVATION_PINS.get(aid)
    if record and record['pin'] == user_pin and time.time() < record['expiry']:
        # PIN Correct! Queue the KILL command for the agent
        PENDING_COMMANDS[aid] = {"command": "DEACTIVATE_SHIELD", "path": user_pin}
        DEACTIVATION_PINS.pop(aid, None)
        log_manager(f"AUTHORIZATION GRANTED: Agent {aid} disarming shields.")
        return redirect(url_for('home', view='summary'))
    return "Invalid or Expired PIN.", 403
@app.route('/trigger_cis/<aid>')
def trigger_cis(aid):
    if not session.get('logged_in'): return redirect(url_for('login'))
    # Set the command for the agent to pick up
    PENDING_COMMANDS[aid] = {"command": "CHECK_CIS", "path": ""}
    log_manager(f"Manual CIS Audit initiated for agent: {aid}")
    # Redirect back to the same tab
    return redirect(url_for('home', view='agent_details', agent_id=aid, tab='cis'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = sqlite3.connect('edr.db')
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        
        if user:
            # 1. Generate 6-digit 2FA PIN
            code = str(random.randint(100000, 999999))
            expiry = (datetime.now(PKT) + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
            
            # 2. Save to 2FA Table
            conn.execute('INSERT OR REPLACE INTO two_factor (username, code, expiry) VALUES (?, ?, ?)', (username, code, expiry))
            conn.commit()
            conn.close()

            # 3. Send Email using your existing credentials
            # Subject changed to 'Login Verification'
            email_sent = send_security_email("own email", code, "MANAGER_LOGIN")
            
            if email_sent:
                logger.info(f"[AUTH] 2FA Code sent to admin for user: {username}")
            else:
                # EMERGENCY BYPASS: If email fails, log the code to the terminal
                print(f"\n[!!!] EMAIL FAILURE: Manual 2FA Bypass Code for {username} is: {code}\n")
                logger.error(f"[AUTH] Email failed. EMERGENCY CODE PRINTED TO TERMINAL: {code}")

            # 4. Redirect to Verification Page
            session['temp_user'] = username
            return redirect(url_for('verify'))
        else:
            conn.close()
            logger.warning(f"[AUTH] FAILED login attempt for username '{username}' from {request.remote_addr}")
            error = "Invalid Credentials. Please try again."

    return render_template('login.html', error=error)
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    error = None
    if 'temp_user' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user_code = request.form.get('otp')
        username = session['temp_user']
        
        conn = sqlite3.connect('edr.db')
        row = conn.execute('SELECT code, expiry FROM two_factor WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if row:
            db_code, expiry = row
            now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
            
            if now < expiry and user_code == db_code:
                # SUCCESS: Finalize Login
                session.pop('temp_user', None)
                session['logged_in'] = True
                session['user'] = username
                logger.info(f"[AUTH] User '{username}' completed 2FA and access granted.")
                return redirect(url_for('home'))
            else:
                error = "Invalid or Expired Code. Check your email or Manager Logs."
        else:
            error = "Session error. Please try logging in again."
            
    return render_template('verify.html', error=error)
#@app.route('/verify', methods=['GET', 'POST'])
#def verify():
 #   error = None
  #  if 'temp_user' not in session:
   #     return redirect(url_for('login'))
        
   # if request.method == 'POST':
    #    user_code = request.form.get('otp')
     #   username = session['temp_user']
        
      #  conn = sqlite3.connect('edr.db')
       # row = conn.execute('SELECT code, expiry FROM two_factor WHERE username = ?', (username,)).fetchone()
        #conn.close()
        
        #if row:
         #   db_code, expiry = row
          #  now = datetime.now(PKT).strftime("%Y-%m-%d %H:%M:%S")
            
           # if now < expiry and user_code == db_code:
            #    session.pop('temp_user', None)
             #   session['logged_in'] = True
              #  session['user'] = username
               # return redirect(url_for('home'))
            #else:
             #   error = "Invalid or Expired Code."
        #else:
            #error = "Session error. Please login again."
            
    #return render_template('verify.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
@app.route('/restart_manager')
def restart_manager():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Start the shutdown timer in the background
    def delayed_exit():
        time.sleep(3) # Give the server 3 seconds to finish sending the web page
        os._exit(0)

    threading.Thread(target=delayed_exit).start()

    # Create the response first, then return it
    resp = make_response('''
        <body style="background:#0a0c10;color:white;text-align:center;padding-top:100px;font-family:sans-serif;">
            <h1 style="color:#58a6ff;">🔄 Restarting Manager...</h1>
            <p style="color:#8b949e;">The EDR Defender service is rebooting.</p>
            <p>You will be redirected automatically in 10 seconds.</p>
            <script>
                setTimeout(function(){ window.location.href = "/"; }, 10000);
            </script>
        </body>
    ''')
    return resp
#behavior new flask routes
@app.route('/add_behavior_rule', methods=['POST'])
def add_behavior_rule():
    parent = request.form.get('parent_proc').lower().strip()
    child = request.form.get('child_proc').lower().strip()
    target = request.form.get('target_agent')
    if parent and child:
        conn = sqlite3.connect('edr.db')
        conn.execute("INSERT INTO behavior_rules (parent, child, agent_id) VALUES (?, ?, ?)", (parent, child, target))
        conn.commit(); conn.close()
    return redirect(url_for('home', view='policy'))

@app.route('/del_behavior_rule/<int:id>')
def del_behavior_rule(id):
    conn = sqlite3.connect('edr.db')
    conn.execute("DELETE FROM behavior_rules WHERE id = ?", (id,))
    conn.commit(); conn.close()
    return redirect(url_for('home', view='policy'))
def run_file_relay():
    """Starts a hardened HTTP server to serve the uploads folder on Port 5000."""
    class ProtectedFileHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            # Force the server to only look inside the UPLOAD_FOLDER
            super().__init__(*args, directory=UPLOAD_FOLDER, **kwargs)
        
        def log_message(self, format, *args):
            # Log every download attempt to the Manager console for debugging
            logger.info(f"FILE_RELAY: {self.address_string()} requested {args[0]}")

    try:
        # Use allow_reuse_address so you can restart the manager quickly
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", 5000), ProtectedFileHandler) as httpd:
            print("[+] File Relay (HTTP) listening on port 5000")
            httpd.serve_forever()
    except Exception as e:
        print(f"[-] File Relay Error: {e}")
def run_grpc():
    with open('server.key', 'rb') as f: priv = f.read()
    with open('server.crt', 'rb') as f: cert = f.read()
    creds = grpc.ssl_server_credentials(((priv, cert),))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=200))
    edr_pb2_grpc.add_EDRServiceServicer_to_server(EDRServicer(), server)
    server.add_secure_port('0.0.0.0:50051', creds)
    server.start(); server.wait_for_termination()

#if __name__ == "__main__":
 #   init_db()
  #  threading.Thread(target=run_grpc, daemon=True).start()
   # threading.Thread(target=monitor_agent_health, daemon=True).start()
    #from waitress import serve
    #print("EDR Defender Production Server live on http://192.168.3.129:8080")
    #serve(app, host='0.0.0.0', port=8080)
if __name__ == "__main__":
    init_db()
    logger.info("[SYSTEM] EDR Defender Manager Engine Started.")
    logger.info(f"[SYSTEM] Security Dashboard live on https://{MANAGER_IP}:8080")
    # Start the secure gRPC server for Agents
    threading.Thread(target=run_file_relay, daemon=True).start()
    threading.Thread(target=run_grpc, daemon=True).start()
    # Start the health monitor
    threading.Thread(target=monitor_agent_health, daemon=True).start()
    threading.Thread(target=purge_low_score_ips, daemon=True).start()
    
    print("EDR Defender SECURE Dashboard live on https://10.0.107.251:8080")
    # We use the existing certificates to secure the Web Traffic
    #app.run(host='0.0.0.0', port=8080, ssl_context=('server.crt', 'server.key'))
    app.run(host='0.0.0.0', port=8080, ssl_context=(CERT_FILE, KEY_FILE))
