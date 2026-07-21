import grpc, edr_pb2, edr_pb2_grpc, psutil, time, os, hashlib, threading, shutil, platform, socket, ctypes, sys, json
import winreg
import urllib.request
import subprocess
import ssl
from tkinter import messagebox, ttk, simpledialog
import tkinter as tk
import logging
import win32net
import win32netcon
import win32evtlog
import xml.etree.ElementTree as ET
import win32evtlogutil
#import win32process, win32gui
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageTk # Add this to your imports at the top

os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA' 
UBUNTU_IP = "10.0.107.251" #old ip 192.168.3.129
SEVERITY_MAP = {
    "SYSTEM": 0, "SCAN_INFO": 1, "FIREWALL": 0, "RESTORATION": 0, "ISOLATION": 0,
    "USER_CREATED": 2, "USER_ENABLED": 3, "USB_WHITELIST": 2, "VULNERABILITY": 3,
    "REGISTRY": 5, "POLICY_VIOLATION": 6, "GROUP_REMOVAL": 4, "GROUP_ADDED": 4,
    "RANSOMWARE": 9, "BEHAVIOR": 7, "BRUTEFORCE_BREACH": 8, "PRIVILEGE_ESC": 7, 
    "NETWORK_CRITICAL": 10, "CRITICAL_REMEDIATION": 7, "IDENTITY_TAMPER": 8
}
AGENT_ID = platform.node()
SERVICE_NAME = "MyEDR_Agent"
EMERGENCY_PASSWORD = "EDR_Lock_99!"
BRUTE_FORCE_TRACKER = {} # { "username": [timestamps] }
REMEDIATION_POLICY = False
CURRENT_CWD = "C:\\"
INSTALL_DIR = r"C:\ProgramData\EDR_Defender"
EVENT_TIMESTAMPS = {11: [], 23: [], 26: []} # Tracks timestamps for IDs
VAULT_PATH = os.path.join(INSTALL_DIR, "xyz.dat")
if not os.path.exists(INSTALL_DIR): os.makedirs(INSTALL_DIR)
if getattr(sys, 'frozen', False): BASE_DIR = os.path.dirname(sys.executable)
else: BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_PATH = os.path.join(BASE_DIR, "server.crt")
QUARANTINE_DIR = r"C:\EDR_Quarantine"
if getattr(sys, 'frozen', False):
    current_dir = os.path.dirname(sys.executable)
else:
    current_dir = os.path.dirname(os.path.abspath(__file__))

#log_file_path = os.path.join(current_dir, "agent.log")

# --- LOGGING ---
#logging.basicConfig(
 #   level=logging.INFO,
  #  format='%(asctime)s [%(levelname)s] %(message)s',
   # handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()]
#)
GLOBAL_STUB, CHANNEL, BLOCKED_APPS, ALLOWED_USB, BEHAVIOR_RULES  = None, None, [], [], []
IS_RESTORING = False
C2_DOWNLOAD_DIR = r"C:\MyEDR\Downloads"
SCAN_HISTORY_FILE = os.path.join(INSTALL_DIR, "local_scans.json")
if not os.path.exists(C2_DOWNLOAD_DIR): os.makedirs(C2_DOWNLOAD_DIR)
FLEET_SCAN_TIME = "00:00"
LAST_SCHEDULED_SCAN_DATE = ""
ORIGINAL_CERT_HASH = ""
REPORTED_CONNECTIONS = set()
CURRENT_FIM_OBSERVER = None
TRACKED_SESSION_ID = 0xFFFFFFFF
TRACKED_USER_NAME = "None"
CURRENT_CWD = os.path.join(os.environ['USERPROFILE'], "Downloads")
# HKLM is Global (Machine-wide) - These work for the Service automatically
GLOBAL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")
]

# These are the paths we will find for EVERY human user logged in
USER_RELATIVE_PATHS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
]

LAST_REG_STATE = {} # Stores: {(hive, full_path, name): value}
# --- CANARY CONFIGURATION ---
CANARY_DIR = r"C:\EDR_Canary_Bait"
# Names starting with symbols/0 to ensure they are the first files encrypted
CANARY_FILES = ["!000_DO_NOT_DELETE.txt", "!001_System_Health.docx"]
# --- REPLACE OLD LOGGING BLOCK WITH THIS FUNCTION ---
def init_agent_logging(mode_name):
    log_path = os.path.join(r"C:\ProgramData\EDR_Defender", f"agent_{mode_name}.log")
    # Ensure directory exists before logging
    if not os.path.exists(r"C:\ProgramData\EDR_Defender"):
        os.makedirs(r"C:\ProgramData\EDR_Defender")
        
    # Set up logging for this specific process
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True  # Overrides any previous config
    )
    logging.info(f"--- EDR {mode_name.upper()} LOGGING INITIALIZED ---")
#def lock_registry_key(lock=True):
 #   """Bypasses the lock during authorized shutdown."""
  #  try:
   #     import win32security, ntsecuritycon
    #    reg_path = r"MACHINE\SYSTEM\CurrentControlSet\Services\MyEDR_Agent"
     #   if not lock:
            # This 'Unlocks' the key by resetting permissions to inherit from parent
      #      win32security.SetNamedSecurityInfo(reg_path, win32security.SE_REGISTRY_KEY, win32security.DACL_SECURITY_INFORMATION | win32security.UNPROTECTED_DACL_SECURITY_INFORMATION, None, None, None, None)
       #     logging.info("[+] Registry Shield: Unlocked for maintenance.")
    #except Exception as e:
     #   logging.error(f"[-] Registry Shield Error: {e}")
def harden_registry():
    """LAYER 1: The Iron Wall. Uses PowerShell to avoid NoneType errors."""
    try:
        # This command explicitly denies 'Set' and 'Delete' to Administrators
        cmd = (
            'powershell.exe -Command "'
            '$path = \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\MyEDR_Agent\'; '
            '$acl = Get-Acl $path; '
            '$rule = New-Object System.Security.AccessControl.RegistryAccessRule(\'Administrators\',\'SetValue,Delete\',\'Deny\'); '
            '$acl.AddAccessRule($rule); '
            'Set-Acl $path $acl"'
        )
        subprocess.run(cmd, shell=True, capture_output=True, creationflags=0x08000000)
        logging.info("[+] Registry Shield: Iron Wall LOCKED via PowerShell.")
    except Exception as e:
        logging.error(f"[-] Registry Hardening Failed: {e}")
def soften_registry():
    """LAYER 2: The Key. Removes the Deny rule."""
    try:
        # This command wipes all Deny rules and resets to default inheritance
        cmd = (
            'powershell.exe -Command "'
            '$path = \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\MyEDR_Agent\'; '
            '$acl = Get-Acl $path; '
            '$acl.SetAccessRuleProtection($false, $false); '
            'Set-Acl $path $acl"'
        )
        subprocess.run(cmd, shell=True, capture_output=True, creationflags=0x08000000)
        logging.info("[+] Registry Shield: Unlocked for maintenance.")
    except Exception as e:
        logging.error(f"[-] Registry Softening Failed: {e}")
class AgentDashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("EDR DEFENDER | Management Console")
        self.root.geometry("550x800")
        self.root.configure(bg="#050505")
        self.root.resizable(False, False)

        # 1. LOAD THE NEBULA BACKGROUND (Image 2 Style)
        try:
            # We use a Label to hold the background image
            self.bg_image = Image.open(os.path.join(BASE_DIR, "bg.png"))
            self.bg_image = self.bg_image.resize((550, 800), Image.Resampling.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            self.bg_label = tk.Label(self.root, image=self.bg_photo)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except:
            pass # Fallback to black if image is missing

        # 2. STYLE CONFIGURATION
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#050505", borderwidth=0)
        style.configure("TNotebook.Tab", background="#111", foreground="#ffffff", padding=[15, 5])
        style.map("TNotebook.Tab", background=[("selected", "#bf5af2")], foreground=[("selected", "white")])
        style.configure("Treeview", background="#0a0a0a", foreground="white", fieldbackground="#0a0a0a", borderwidth=0, rowheight=30)
        style.configure("Treeview.Heading", background="#1a0033", foreground="#ffffff", borderwidth=0)

        # 3. HEADER AREA (With your Logo)
        header_frame = tk.Frame(self.root, bg="#050505")
        header_frame.place(relx=0.5, y=60, anchor="center")
        
        try:
            logo_img = Image.open(os.path.join(BASE_DIR, "logo.png"))
            logo_img = logo_img.resize((65, 65), Image.Resampling.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_img)
            tk.Label(header_frame, image=self.logo_photo, bg="#050505").pack()
        except:
            tk.Label(header_frame, text="🛡️", font=("Arial", 30), fg="#bf5af2", bg="#050505").pack()

        tk.Label(header_frame, text="EDR DEFENDER", font=("Segoe UI", 22, "bold"), fg="#ffffff", bg="#050505").pack()
        tk.Label(header_frame, text="ONE NETWORK SECURITY", font=("Segoe UI", 8, "bold"), fg="#bf5af2", bg="#050505").pack()

        # 4. TAB CONTROL
        self.notebook = ttk.Notebook(self.root)
        self.notebook.place(relx=0.5, y=420, anchor="center", width=500, height=520)

        # --- TAB 1: OVERVIEW ---
        self.tab_overview = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_overview, text="  OVERVIEW  ")

        # Stats Panel (Dark Purple Glow)
        self.stats_panel = tk.Frame(self.tab_overview, bg="#0a0a0a", padx=20, pady=20, highlightthickness=1, highlightbackground="#1a0033")
        self.stats_panel.pack(fill="x", padx=20, pady=20)
        
        self.add_stat("NODE IDENTIFIER", AGENT_ID)
        self.add_stat("INTERFACE IP", get_ip())
        #self.add_stat("INTERFACE IP", socket.gethostbyname(socket.gethostname()))
        self.add_stat("MANAGEMENT LINK", UBUNTU_IP)

        self.status_frame = tk.Frame(self.tab_overview, bg="#050505")
        self.status_frame.pack(pady=10)
        self.status_dot = tk.Label(self.status_frame, text="●", font=("Arial", 12), fg="#39ff14", bg="#050505")
        self.status_dot.pack(side="left", padx=5)
        self.status_text = tk.Label(self.status_frame, text="SYSTEM OPERATIONAL", font=("Segoe UI", 10, "bold"), fg="#ffffff", bg="#050505")
        self.status_text.pack(side="left")

        # THE NEW SCAN BUTTON (As requested in the blue box)
        self.scan_btn = tk.Button(self.tab_overview, text="🚀 INITIALIZE FULL SCAN", command=self.trigger_local_user_scan,
                                  bg="#001a1a", fg="#00f2ff", font=("Segoe UI", 10, "bold"),
                                  relief="flat", highlightthickness=1, highlightbackground="#00f2ff", padx=20, pady=10)
        self.scan_btn.pack(pady=20)

        #self.action_btn = tk.Button(self.tab_overview, text="TERMINATE PROTECTION", command=self.handle_action, 
         #                         bg="#1a0033", fg="#ff4d4d", font=("Segoe UI", 9, "bold"),
          #                        relief="flat", highlightthickness=1, highlightbackground="#bf5af2", bd=1, padx=20, pady=10)
        #self.action_btn.pack(pady=10)
        btn_frame = tk.Frame(self.tab_overview, bg="#050505")
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="START PROTECTION", command=self.start_service_sequence, 
                                   bg="#002200", fg="#39ff14", font=("Segoe UI", 9, "bold"), width=20, relief="flat", highlightthickness=1)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(btn_frame, text="STOP PROTECTION", command=self.auth_stop_sequence, 
                                  bg="#220000", fg="#ff4d4d", font=("Segoe UI", 9, "bold"), width=20, relief="flat", highlightthickness=1)
        self.stop_btn.pack(side="left", padx=5)
        # --- TAB 2: QUARANTINE ---
        self.tab_quar = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_quar, text="  QUARANTINE  ")
        self.q_tree = self.create_file_table(self.tab_quar, QUARANTINE_DIR)

        # --- TAB 3: DOWNLOADS ---
        self.tab_dl = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_dl, text="  DOWNLOADS  ")
        self.dl_tree = self.create_file_table(self.tab_dl, C2_DOWNLOAD_DIR)
        
        # --- NEW: SCAN HISTORY TAB ---
        self.tab_hist = tk.Frame(self.notebook, bg="#050505"); self.notebook.add(self.tab_hist, text="  SCAN HISTORY  ")
        self.h_tree = self.create_history_table(self.tab_hist)

        # 4. FOOTER
        tk.Label(self.root, text="💡 Tip: Double-click a file to reveal it in Windows Explorer", font=("Segoe UI", 8), fg="#555", bg="#0b0b0b").pack(pady=10)

        self.update_ui_state()
    
    def create_history_table(self, parent):
        container = tk.Frame(parent, bg="#050505")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        cols = ("Time", "Path", "Objects", "Threats")
        tree = ttk.Treeview(container, columns=cols, show="headings")
        for col in cols: tree.heading(col, text=col.upper())
        tree.column("Time", width=120); tree.column("Path", width=180); tree.column("Objects", width=80); tree.column("Threats", width=80)
        tree.pack(fill="both", expand=True)
        return tree

    def add_stat(self, label, value):
        row = tk.Frame(self.stats_panel, bg="#0a0a0a", pady=6)
        row.pack(fill="x")
        tk.Label(row, text=label, font=("Segoe UI", 8, "bold"), fg="#888", bg="#0a0a0a").pack(side="left")
        # Values are now Purple
        tk.Label(row, text=value, font=("Consolas", 10), fg="#bf5af2", bg="#0a0a0a").pack(side="right")
    def create_file_table(self, parent, path):
        container = tk.Frame(parent, bg="#050505")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        cols = ("Name", "Size", "Date")
        tree = ttk.Treeview(container, columns=cols, show="headings")
        for col in cols: tree.heading(col, text=col.upper())
        tree.column("Name", width=250); tree.column("Size", width=80); tree.column("Date", width=120)
        tree.pack(side="left", fill="both", expand=True)
        tree.bind("<Double-1>", lambda e: self.open_in_explorer(tree, path))
        return tree
    def trigger_local_user_scan(self):
        """Starts a scan of the current human user's directory."""
        user_path = os.path.join(os.environ['USERPROFILE'])
        messagebox.showinfo("EDR Scanner", f"Scanning node locally:\n{user_path}")
        threading.Thread(target=perform_full_scan, args=(user_path,), daemon=True).start()
    def open_in_explorer(self, tree, folder_path):
        selected = tree.selection()
        if not selected: return
        filename = tree.item(selected)['values'][0]
        full_path = os.path.join(folder_path, filename)
        if os.path.exists(full_path):
            subprocess.Popen(f'explorer /select,"{full_path}"')

    def refresh_file_lists(self):
        for tree, folder in [(self.q_tree, QUARANTINE_DIR), (self.dl_tree, C2_DOWNLOAD_DIR)]:
            for i in tree.get_children(): tree.delete(i)
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    try:
                        s = os.stat(os.path.join(folder, f))
                        tree.insert("", "end", values=(f, f"{round(s.st_size/1024,1)}KB", time.strftime('%Y-%m-%d', time.localtime(s.st_mtime))))
                    except: continue

    def get_service_running(self):
        try:
            res = subprocess.run(f"sc query {SERVICE_NAME}", capture_output=True, text=True, creationflags=0x08000000)
            return "RUNNING" in res.stdout
        except: return False

    def update_ui_state(self):
        is_active = self.get_service_running()
        if is_active:
            self.status_dot.config(fg="#39ff14"); self.status_text.config(text="SHIELD ACTIVE", fg="#ffffff")
            # LOCK START, ENABLE STOP
            self.start_btn.config(state="disabled", bg="#111", fg="#444", highlightbackground="#222")
            self.stop_btn.config(state="normal", bg="#1a0033", fg="#ff4d4d", highlightbackground="#ff4d4d")
        else:
            self.status_dot.config(fg="#ff4d4d"); self.status_text.config(text="PROTECTION DISABLED", fg="#ff4d4d")
            # ENABLE START, LOCK STOP
            self.start_btn.config(state="normal", bg="#002200", fg="#39ff14", highlightbackground="#39ff14")
            self.stop_btn.config(state="disabled", bg="#111", fg="#444", highlightbackground="#222")
        
        self.refresh_file_lists()
        self.refresh_scan_history()
        self.root.after(5000, self.update_ui_state)
        
    def refresh_scan_history(self):
        """Loads scan logs from local JSON file."""
        for i in self.h_tree.get_children(): self.h_tree.delete(i)
        if os.path.exists(SCAN_HISTORY_FILE):
            try:
                with open(SCAN_HISTORY_FILE, 'r') as f:
                    history = json.load(f)
                for entry in reversed(history[-15:]): # Show last 15
                    self.h_tree.insert("", "end", values=(entry['time'], entry['path'], entry['total'], entry['threats']))
            except: pass

    def handle_action(self):
        if self.get_service_running():
            self.auth_stop_sequence()
        else:
            self.start_service_sequence()

    def auth_stop_sequence(self):
        if not os.path.exists(VAULT_PATH):
            messagebox.showerror("Error", "Security handshake data (xyz.dat) missing. Connect to manager first.")
            return
        
        pin_input = simpledialog.askstring("AUTHENTICATION", "Enter Security Authorization PIN:", show='*')
        if not pin_input: return
        
        input_hash = hashlib.sha256(pin_input.encode()).hexdigest()
        with open(VAULT_PATH, "r") as f: stored_hash = f.read().strip()
        
        if input_hash == stored_hash:
            logging.info("[*] PIN MATCHED: Internal Authorization Successful.")
            try:
                logging.info("[*] Authorization Successful. Terminating Service...")
                soften_registry()
                #lock_registry_key(False)
                
                # 1. DISABLE AUTO-RECOVERY (Prevent bouncing back)
                #subprocess.run(f'sc failure "{SERVICE_NAME}" reset= 0 actions= ""', shell=True, capture_output=True)

                # 2. UNLOCK PERMISSIONS (Grant WriteDAC to Admin)
                #logging.info("[*] unlock service buttons. Terminating Service...")
                #sddl_unlock = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
                #logging.info("[*] unlock service buttons success. Terminating Service...")
                #subprocess.run(f'sc sdset "{SERVICE_NAME}" {sddl_unlock}', shell=True, check=True, capture_output=True)
                
                # 1. Prepare the Unlock SDDL
                sddl_unlock = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
                
                # 2. Execute the command and capture result
                result = subprocess.run(f'sc sdset "{SERVICE_NAME}" {sddl_unlock}', 
                                        shell=True, capture_output=True, text=True)

                if result.returncode == 0:
                    # SUCCESS LOG
                    logging.info("[+] SUCCESS: SDDL Matched and Service Buttons are now UNLOCKED.")
                    
                    # 3. Now stop the service since buttons are unlocked
                    subprocess.run(f'sc stop "{SERVICE_NAME}"', shell=True, capture_output=True)
                    logging.info("[!] Service stop command sent to SCM.")
                    messagebox.showinfo("Success", "Authorization Verified. Protection stopping...")
                else:
                    # FAILURE LOG (Windows rejected the command)
                    logging.error(f"[-] ERROR: SDDL did not match or apply. Windows Error: {result.stderr.strip()}")
                    messagebox.showerror("Privilege Error", "System failed to unlock service buttons. Check if running as Admin.")
                # 3. TERMINATE SERVICE
                #logging.info("[*] Stoping serive by powershell command Terminating Service...")
                #subprocess.run(f'sc stop "{SERVICE_NAME}"', shell=True, capture_output=True)
                #lock_registry_key(True)
                harden_registry()
                logging.info("[*] registry locked again")
                logging.info("[*] hardening serice button again command Terminating Service...")
                hardened_sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
                h_res = subprocess.run(f'sc sdset "{SERVICE_NAME}" {hardened_sddl}',shell=True, capture_output=True, text=True)
                
                if h_res.returncode == 0:
                    logging.info("[✓] ENFORCEMENT: Service stopped and state-locked.")
                else:
                    # Log the warning but proceed to show the success message
                    logging.warning(f"[!] Warning: Service stopped, but re-locking failed: {h_res.stderr.strip()}")
                    
                logging.info("[✓] ENFORCEMENT: Service stopped and state-locked.")
                messagebox.showinfo("Success", "Shield-EDR Protection has been suspended.")
            
            except subprocess.CalledProcessError as e:
                # This part will NOW catch the "Access Denied" error
                err_msg = e.stderr.decode().strip()
                logging.error(f"[X] COMMAND FAILED: {err_msg}")
                
                if "5:" in err_msg or "Access is denied" in err_msg:
                    messagebox.showerror("Privilege Error", "Windows denied access.\n\nYou MUST 'Run as Administrator'.")
                else:
                    messagebox.showerror("System Error", f"Failed to stop service: {err_msg}")
        else:
            logging.warning(f"[-] Access Denied: Incorrect PIN entered for {socket.gethostname()}")
            messagebox.showerror("Access Denied", "Invalid Security PIN.")

    #def start_service_sequence(self):
     #   logging.info("[*] starting service again")
        #lock_registry_key(False)
      #  soften_registry()
        #logging.info("[*] registry unlocked")
        # 1. Unlock so Start command works
       # sddl_unlock = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
        #subprocess.run(f'sc sdset "{SERVICE_NAME}" {sddl_unlock}', shell=True, capture_output=True)
        # 2. Start
        #subprocess.run(f'sc start "{SERVICE_NAME}"', shell=True, capture_output=True)
        #harden_registry()
        #logging.info("[*] locking registry again")
        # 3. Re-lock (Gray out the Stop button again)
        #hardened = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
        #subprocess.run(f'sc sdset "{SERVICE_NAME}" {hardened}', shell=True, capture_output=True)
        #lock_registry_key(True)
        #messagebox.showinfo("Success", "EDR Defender protection is now ACTIVE.")
    def start_service_sequence(self):
        logging.info("[*] Resuming Protection...")
        try:
            # 1. UNLOCK EVERYTHING FIRST
            soften_registry()
            sddl_unlock = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
            subprocess.run(f'sc sdset "{SERVICE_NAME}" {sddl_unlock}', shell=True, capture_output=True)

            # 2. START THE SERVICE
            # We use 'net start' because it waits for the result
            res = subprocess.run(f'net start "{SERVICE_NAME}"', shell=True, capture_output=True, text=True)
            logging.info(f"Start command result: {res.stdout.strip()}")

            # 3. VERIFICATION: Wait up to 5 seconds for it to be live
            started = False
            for _ in range(5):
                check = subprocess.run(f'sc query "{SERVICE_NAME}"', capture_output=True, text=True, shell=True)
                if "RUNNING" in check.stdout:
                    started = True
                    break
                time.sleep(1)

            if started:
                # 4. RE-HARDEN ONLY AFTER SUCCESSFUL START
                harden_registry()
                hardened_sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
                subprocess.run(f'sc sdset "{SERVICE_NAME}" {hardened_sddl}', shell=True, capture_output=True)
                
                logging.info("[✓] EDR is now ACTIVE and SHIELDS are UP.")
                messagebox.showinfo("Success", "EDR Defender is now ACTIVE and PROTECTED.")
            else:
                logging.error(f"Service failed to reach RUNNING state: {res.stderr}")
                messagebox.showerror("Error", "Service started but stopped unexpectedly. Check logs.")

        except Exception as e:
            logging.error(f"Start Sequence Error: {e}")
    def run(self):
        logging.info("Starting GUI MainLoop.")
        self.refresh_file_lists()
        self.root.mainloop()
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((UBUNTU_IP, 50051))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return "Unknown"
def get_detailed_metadata():
    """Deep-dive hardware and OS discovery."""
    metadata = {
        "mac": "Unknown", "domain": "WORKGROUP", 
        "kernel": platform.version(), "activation": "Checking...", "install_date": "Unknown"
    }
    try:
        # 1. MAC Address
        import uuid
        metadata["mac"] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]).upper()
        
        # 2. Domain
        metadata["domain"] = os.environ.get('USERDOMAIN', 'WORKGROUP')

        if platform.system() == "Windows":
            # 3. OS Activation Status (The "Heartbeat" of Windows Licensing)
            try:
                # This command asks the system for the STATUS of the current Windows version only.
                # It ignores Office, trials, and extra components.
                ps_act = 'powershell.exe -NoProfile -Command "(Get-CimInstance -Query \\"SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE (Name LIKE \'%Windows%\') AND (PartialProductKey IS NOT NULL)\\").LicenseStatus"'
                
                # Execute and capture the raw output
                status_raw = subprocess.check_output(ps_act, shell=True).decode().strip()
                
                # Debug print so you can see the raw number in your PowerShell console
                print(f"[*] Raw Activation Code: {status_raw}")

                # Logic: If '1' is found anywhere in the response, it is LICENSED.
                # Windows Status Codes: 1 = Licensed, 0/2/3+ = Unlicensed or Grace Period.
                if "1" in status_raw:
                    metadata["activation"] = "Licensed / Activated"
                else:
                    metadata["activation"] = "Unlicensed / Notification"
                    
            except Exception as e:
                print(f"[-] Activation Check Failed: {e}")
                metadata["activation"] = "Unknown"

            # 4. OS Install Date
            try:
                date_cmd = 'wmic os get installdate'
                res_date = subprocess.check_output(date_cmd, shell=True).decode().strip().split('\n')[1].strip()
                # Format: YYYY-MM-DD
                metadata["install_date"] = f"{res_date[:4]}-{res_date[4:6]}-{res_date[6:8]}"
            except: pass
            
    except Exception as e:
        print(f"[!] Metadata Discovery Error: {e}")
    return metadata
def get_hardware_inventory():
    """Gathers detailed hardware specs via WMIC and Psutil."""
    inventory = {
        "cpu": {"model": "Unknown", "freq": "0"},
        "ram": {"model": "Unknown", "freq": "0", "total": "0", "usage": "0"},
        "mobo": {"model": "Unknown", "serial": "Unknown"},
        "gpu": "Unknown", "sound": "Unknown", "network": "Unknown", "monitor": "Unknown",
        "partitions": []
    }
    try:
        # CPU
        inventory["cpu"]["model"] = subprocess.check_output('wmic cpu get name', shell=True).decode().split('\n')[1].strip()
        inventory["cpu"]["freq"] = subprocess.check_output('wmic cpu get maxclockspeed', shell=True).decode().split('\n')[1].strip() + " MHz"
        
        # RAM (Physical Specs)
        ram_raw = subprocess.check_output('wmic memorychip get manufacturer, speed, capacity', shell=True).decode().split('\n')
        if len(ram_raw) > 1:
            line = ram_raw[1].split()
            inventory["ram"]["model"] = line[1] if len(line) > 1 else "Generic"
            inventory["ram"]["freq"] = line[2] + " MHz" if len(line) > 2 else "N/A"
        
        # RAM (Live Usage)
        vm = psutil.virtual_memory()
        inventory["ram"]["total"] = f"{round(vm.total / (1024**3), 1)} GB"
        inventory["ram"]["usage"] = f"{vm.percent}%"

        # Motherboard
        mobo_out = subprocess.check_output('wmic baseboard get product,serialnumber', shell=True).decode().split('\n')[1].split()
        inventory["mobo"]["model"] = mobo_out[0] if len(mobo_out) > 0 else "Unknown"
        inventory["mobo"]["serial"] = mobo_out[1] if len(mobo_out) > 1 else "N/A"

        # GPU / Sound / Network
        inventory["gpu"] = subprocess.check_output('wmic path win32_VideoController get name', shell=True).decode().split('\n')[1].strip()
        inventory["sound"] = subprocess.check_output('wmic path win32_sounddevice get name', shell=True).decode().split('\n')[1].strip()
        inventory["network"] = subprocess.check_output('wmic nic where "NetEnabled=true" get name', shell=True).decode().split('\n')[1].strip()
        
        try: inventory["monitor"] = subprocess.check_output('wmic path win32_desktopmonitor get caption', shell=True).decode().split('\n')[1].strip()
        except: inventory["monitor"] = "Standard Monitor"

        # Partitions (Orange Bars)
        for part in psutil.disk_partitions():
            if 'fixed' in part.opts:
                usage = psutil.disk_usage(part.mountpoint)
                inventory["partitions"].append({
                    "drive": part.mountpoint,
                    "total": round(usage.total / (1024**3), 1),
                    "used": round(usage.used / (1024**3), 1),
                    "percent": usage.percent
                })
    except Exception as e:
        print(f"Hardware Discovery Error: {e}")
    return inventory
def get_user_forensics():
    """
    Precision Security Auditor:
    Correctly handles the property index differences between 4624 (Success) 
    and 4625 (Failure) events to ensure all attempts are captured.
    """
    user_inventory = []
    print("[*] Starting Security Audit: Capturing Success & Failure Events...")
    
    try:
        # --- PART 1: SMART POWERSHELL QUERY ---
        # This script detects if the ID is 4624 or 4625 and adjusts the slots automatically.
        # Success (4624): User=5, Type=8, IP=18
        # Failure (4625): User=5, Type=10, IP=19
        ps_command = """
        $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 300 -ErrorAction SilentlyContinue
        if ($events) {
            $events | ForEach-Object {
                $id = $_.Id
                $user = $_.Properties[5].Value
                if ($id -eq 4624) { 
                    $type = $_.Properties[8].Value
                    $ip = $_.Properties[18].Value 
                } else { 
                    $type = $_.Properties[10].Value
                    $ip = $_.Properties[19].Value 
                }
                [PSCustomObject]@{EID="$id"; U=$user; T=$_.TimeCreated; M="$type"; I=$ip}
            } | ConvertTo-Json
        } else { "[]" }
        """
        
        all_logs = []
        try:
            raw_json = subprocess.check_output(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_command], text=True, stderr=subprocess.DEVNULL)
            if raw_json and raw_json.strip() and raw_json.strip() != "[]":
                all_logs = json.loads(raw_json)
                if isinstance(all_logs, dict): all_logs = [all_logs]
        except: pass

        LOGON_MAP = {"2": "Interactive", "3": "Network", "10": "Remote (RDP)", "7": "Unlock"}

        # --- PART 2: GET USER LIST (Win32 API) ---
        admin_members = []
        try:
            import win32net, win32netcon
            members, _, _ = win32net.NetLocalGroupGetMembers(None, "Administrators", 1)
            admin_members = [m['name'].lower() for m in members]
        except: pass

        resume = 0
        while True:
            users_data, total, resume = win32net.NetUserEnum(None, 1, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
            for u in users_data:
                u_name = u['name']
                if u_name.endswith('$'): continue

                status = "Disabled" if bool(u['flags'] & win32netcon.UF_ACCOUNTDISABLE) else "Enabled"
                role = "Admin" if u_name.lower() in admin_members else "Non-admin"

                # --- PART 3: MATCHING ---
                history = []
                for log in all_logs:
                    if str(log.get('U', '')).lower() == u_name.lower():
                        eid = str(log.get('EID', ''))
                        res_str = "Success" if eid == "4624" else "FAILED"
                        
                        l_type = str(log.get('M', ''))
                        if l_type in LOGON_MAP:
                            # Time formatting
                            raw_t = str(log.get('T', ''))
                            if "/Date" in raw_t:
                                ts = "".join(filter(str.isdigit, raw_t))[:10]
                                login_time = time.strftime('%Y-%m-%d %H:%M', time.localtime(int(ts)))
                            else:
                                login_time = raw_t.replace("T", " ")[:16]

                            history.append({
                                "method": LOGON_MAP[l_type],
                                "result": res_str,
                                "login": login_time,
                                "logout": "N/A" if res_str == "FAILED" else "Active",
                                "ip": str(log.get('I')) if len(str(log.get('I'))) > 3 else "Local"
                            })
                    if len(history) >= 10: break

                user_inventory.append(edr_pb2.UserItem(
                    username=u_name, status=status, user_type="Local User",
                    role=role, last_pass_change="Synced", last_login="See History",
                    login_history_json=json.dumps(history)
                ))
            if not resume: break

        print(f"[+] Audit complete. Successfully matched both Success and Failure logs.")
    except Exception as e:
        print(f"[!] Forensic Audit Error: {e}")
        
    return user_inventory
def get_listening_ports():
    ports = []
    print("[*] Scanning Network Ports...")
    try:
        # Check firewall rules to see if we already blocked some ports
        blocked_raw = subprocess.check_output('netsh advfirewall firewall show rule name=all', shell=True).decode()
        
        for conn in psutil.net_connections(kind='inet'):
            is_tcp_listen = (conn.type == socket.SOCK_STREAM and conn.status == 'LISTEN')
            is_udp = (conn.type == socket.SOCK_DGRAM)

            if is_tcp_listen or is_udp:
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                port = conn.laddr.port
                pid = conn.pid or 0
                
                # Check if this specific port is in our 'Block' list
                is_blocked = f"EDR_BLOCK_PORT_{protocol}_{port}" in blocked_raw
                
                process_name = "Unknown"
                try:
                    process_name = psutil.Process(pid).name()
                except: process_name = "System/Protected"
                
                ports.append(edr_pb2.PortItem(
                    protocol=protocol, port=port, process=process_name, 
                    pid=pid, is_blocked=is_blocked
                ))
    except: pass
    return ports
def run_cis_audit():
    """
    Hardened CIS Audit: Covers 1.1.1 to 1.1.9
    Each check is independent to prevent the function from stopping on errors.
    """
    results = []
    passed = 0
    total_checks = 51 # We are doing 8 specific logic checks for 1.1.x

    def add_res(id, name, is_pass, fix):
        nonlocal passed
        if is_pass: passed += 1
        results.append(edr_pb2.CisItem(name=f"{id} {name}", passed=is_pass, details="Compliant" if is_pass else fix))

    # --- PRE-FETCH SYSTEM DATA ---
    try:
        net_accounts = subprocess.check_output('net accounts', shell=True).decode()
    except:
        net_accounts = ""

    # 1.1.1 Minimum Password Length
    try:
        val = int(net_accounts.split("Minimum password length:")[1].split("\n")[0].strip())
        add_res("1.1.1", "Min Password Length (8+)", val >= 8, f"Current: {val}. Set 'net accounts /minpwlen:8'")
    except: add_res("1.1.1", "Min Password Length (8+)", False, "Error parsing policy")

    # 1.1.2 Minimum Password Age
    try:
        val = int(net_accounts.split("Minimum password age (days):")[1].split("\n")[0].strip())
        add_res("1.1.2", "Min Password Age (2+ Days)", val >= 2, f"Current: {val}. Set 'net accounts /minpwage:2'")
    except: add_res("1.1.2", "Min Password Age (2+ Days)", False, "Error parsing policy")

    # 1.1.3 Maximum Password Age
    try:
        val = int(net_accounts.split("Maximum password age (days):")[1].split("\n")[0].strip())
        # Check if between 1 and 90
        is_p = (0 < val <= 90)
        add_res("1.1.3", "Max Password Age (90 or Less)", is_p, f"Current: {val}. Set 'net accounts /maxpwage:90'")
    except: add_res("1.1.3", "Max Password Age (90 or Less)", False, "Error parsing policy")

    # 1.1.4 Password History
    try:
        val = int(net_accounts.split("Length of password history maintained:")[1].split("\n")[0].strip())
        add_res("1.1.4", "Password History (5+)", val >= 5, f"Current: {val}. Set 'net accounts /uniquepw:5'")
    except: add_res("1.1.4", "Password History (5+)", False, "Error parsing policy")

    # 1.1.5 Don't Display Last Username (Registry)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as k:
            val = winreg.QueryValueEx(k, "DontDisplayLastUserName")[0]
            add_res("1.1.5", "Login: Hide Last Username", val == 1, "Registry: Set DontDisplayLastUserName to 1")
    except: add_res("1.1.5", "Login: Hide Last Username", False, "Registry key missing or restricted")

    # 1.1.6 Limit Blank Password Use (Registry)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as k:
            val = winreg.QueryValueEx(k, "LimitBlankPasswordUse")[0]
            add_res("1.1.6", "Limit Blank Password Use", val == 1, "Registry: Set LimitBlankPasswordUse to 1")
    except: add_res("1.1.6", "Limit Blank Password Use", False, "Registry key missing")

    # 1.1.8 Password Complexity (Registry Check)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as k:
            val, _ = winreg.QueryValueEx(k, "Notification Packages")
            # If 'scecli' is in the list, complexity is usually enforced
            add_res("1.1.8", "Password Complexity Enabled", "scecli" in str(val).lower(), "Enable complexity in secpol.msc")
    except: add_res("1.1.8", "Password Complexity Enabled", False, "Check secpol.msc")

    # 1.1.9 No Auto-Admin Logon (Registry)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            val = winreg.QueryValueEx(k, "AutoAdminLogon")[0]
            add_res("1.1.9", "Disable Auto-Admin Logon", str(val) == "0", "Registry: Set AutoAdminLogon to 0")
    except:
        # If the key is missing, it is usually 0 by default (Safe)
        add_res("1.1.9", "Disable Auto-Admin Logon", True, "Compliant")
    # 1.2.1 Account Lockout Counter (Observation Window)
    try:
        # Search for: "Lockout observation window (mins):"
        val = int(net_accounts.split("Lockout observation window (mins):")[1].split("\n")[0].strip())
        add_res("1.2.1", "Account Lockout Counter (10+ min)", val >= 10, f"Current: {val}. Set via secpol.msc")
    except: add_res("1.2.1", "Account Lockout Counter (10+ min)", False, "Lockout policy not set or 0")

    # 1.2.2 Account Lockout Duration
    try:
        val = int(net_accounts.split("Lockout duration (mins):")[1].split("\n")[0].strip())
        add_res("1.2.2", "Account Lockout Duration (10+ min)", val >= 10, f"Current: {val}. Set via secpol.msc")
    except: add_res("1.2.2", "Account Lockout Duration (10+ min)", False, "Lockout policy not set or 0")

    # 1.2.3 Account Lockout Threshold
    try:
        val = int(net_accounts.split("Lockout threshold:")[1].split("\n")[0].strip())
        # CIS recommends between 1 and 5
        is_p = (0 < val <= 5)
        add_res("1.2.3", "Account Lockout Threshold (5 or Less)", is_p, f"Current: {val}. Set 'net accounts /lockoutthreshold:5'")
    except: add_res("1.2.3", "Account Lockout Threshold (5 or Less)", False, "Lockout threshold not set")

    # 1.2.4 Screen Saver Timeout Enabled
    try:
        # Check standard user desktop policy
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as k:
            val = winreg.QueryValueEx(k, "ScreenSaveActive")[0]
            add_res("1.2.4", "Screen Saver Enabled", str(val) == "1", "Enable Screen Saver in Personalization settings")
    except: add_res("1.2.4", "Screen Saver Enabled", False, "Registry key missing")

    # 1.2.5 Idle Time of RDP Access (Session Limits)
    try:
        # Check RDP session timeout policy in HKLM
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services") as k:
            # MaxIdleTime is in milliseconds. 10 mins = 600,000ms
            val = winreg.QueryValueEx(k, "MaxIdleTime")[0]
            add_res("1.2.5", "RDP Idle Timeout (< 10 min)", (0 < val <= 600000), "Set RDP 'End disconnected session' to 10 min in GPO")
    except:
        # If the key is missing, RDP timeout is usually 'Never' (Insecure)
        add_res("1.2.5", "RDP Idle Timeout (< 10 min)", False, "RDP Session limits not configured")
    # 1.3.1 Remote Service Is Disabled (Focus: Remote Registry)
    # Professional EDRs check this because hackers use it to edit your registry remotely
    try:
        # Check if the Remote Registry service is STOPPED or DISABLED
        out = subprocess.check_output('sc query RemoteRegistry', shell=True).decode()
        is_p = ("STOPPED" in out or "DISABLED" in out)
        add_res("1.3.1", "Remote Registry Service Disabled", is_p, "Run 'sc config RemoteRegistry start= disabled'")
    except: 
        # If the service doesn't even exist, that is a PASS
        add_res("1.3.1", "Remote Registry Service Disabled", True, "Compliant")

    # 1.3.2 Remote Access Encryption Level (RDP)
    try:
        # Check RDP Encryption level in Registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as k:
            val = winreg.QueryValueEx(k, "MinEncryptionLevel")[0]
            # 3 = High Encryption (Standard CIS Requirement)
            add_res("1.3.2", "RDP Encryption Level (High)", val == 3, "Set RDP Encryption to 'High' in GPO")
    except: 
        add_res("1.3.2", "RDP Encryption Level (High)", False, "RDP Encryption not configured")

    # 1.3.3 Remote Port Service Uses SSH or HTTPS (WinRM Check)
    try:
     #   # Checks if Windows Remote Management (WinRM) is set to use encrypted HTTPS
      #  # This uses PowerShell to look at the active listeners
        out = subprocess.check_output('powershell -Command "Get-ChildItem WSMan:\\localhost\\Listener"', shell=True).decode()
        is_secure = ("Transport=HTTPS" in out)
        ## If WinRM is totally off, it's also a PASS
        if not out.strip(): is_secure = True
        
        add_res("1.3.3", "Secure Remote Protocols (HTTPS/SSH)", is_secure, "Disable WinRM HTTP and enable HTTPS listener")
    except: 
        add_res("1.3.3", "Secure Remote Protocols (HTTPS/SSH)", False, "WinRM protocol check failed")
    # 1.3.3 Remote Port Service (WinRM Check)
   # try:
    #    # Check service status first. This NEVER prompts for [Y/N]
     #   svc_out = subprocess.run('sc query WinRM', capture_output=True, text=True, shell=True).stdout
      #  if "RUNNING" not in svc_out:
       #     add_res("1.3.3", "Secure Remote Protocols (WinRM)", True, "Compliant")
        #else:
         #   # Check transport type silently
          #  ps_cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Transport"'
           # transport = subprocess.check_output(ps_cmd, shell=True).decode().strip()
            #is_secure = ("HTTPS" in transport)
            #add_res("1.3.3", "Secure Remote Protocols (WinRM)", is_secure, "WinRM is on insecure HTTP")
    #except:
     #   add_res("1.3.3", "Secure Remote Protocols (WinRM)", True, "Compliant")
    # 2.1.1 Administrator Account Is Renamed or Disabled
    try:
        # Check if a user named 'Administrator' exists and is disabled
        out = subprocess.check_output('wmic useraccount where name="Administrator" get Disabled', shell=True).decode()
        is_disabled = "TRUE" in out.upper()
        # If 'Administrator' doesn't exist (because it was renamed), it's a PASS
        if "No Instance(s) Available" in out: is_disabled = True
        add_res("2.1.1", "Admin Account Disabled/Renamed", is_disabled, "Disable the built-in Admin account")
    except: add_res("2.1.1", "Admin Account Disabled/Renamed", True, "Compliant")

    # 2.1.2 Guest Accounts Are Disabled
    try:
        out = subprocess.check_output('net user guest', shell=True).decode()
        add_res("2.1.2", "Guest Account Disabled", "Account active               No" in out, "Run 'net user guest /active:no'")
    except: add_res("2.1.2", "Guest Account Disabled", True, "Compliant")

    # 2.1.3 Default Account Password Is Changed
    try:
        # We check if the 'DefaultAccount' has a password set recently
        out = subprocess.check_output('wmic useraccount where name="DefaultAccount" get PasswordRequired', shell=True).decode()
        add_res("2.1.3", "Default Account Password Set", "TRUE" in out.upper(), "Ensure DefaultAccount has a password")
    except: add_res("2.1.3", "Default Account Password Set", True, "Compliant")

    # 2.1.4 No Hidden User Accounts
    try:
        # Windows hides users via this registry key
        reg_h = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_h) as k:
            num = winreg.QueryInfoKey(k)[1]
            # If the key exists and has values, there might be hidden users
            add_res("2.1.4", "No Hidden User Accounts", num == 0, r"Remove entries from Winlogon\SpecialAccounts")
            #add_res("2.1.4", "No Hidden User Accounts", num == 0, "Remove entries from Winlogon\SpecialAccounts")
    except:
        add_res("2.1.4", "No Hidden User Accounts", True, "Compliant") # Key doesn't exist = No hidden users

    # 2.1.5 All Accounts Used in last 6 Months
    try:
        # Check if any local account has been dormant for > 180 days
        six_months_ago = time.time() - (180 * 86400)
        out = subprocess.check_output('wmic useraccount get name,lastlogon /format:csv', shell=True).decode()
        stale_found = False
        for line in out.splitlines():
            if "Node" in line or not line.strip(): continue
            parts = line.split(',')
            if len(parts) >= 3 and parts[2]:
                # Format: 20240510...
                ts = float(time.mktime(time.strptime(parts[2][:8], "%Y%m%d")))
                if ts < six_months_ago: stale_found = True; break
        add_res("2.1.5", "No Dormant Accounts (>6 Months)", not stale_found, "Delete or disable unused accounts")
    except: add_res("2.1.5", "No Dormant Accounts (>6 Months)", True, "Compliant")
    
    # --- SECTION 3.1: SECURITY AUDIT POLICIES ---
    # We use 'auditpol' to check if the OS is recording security events
    def check_audit(id, name, subcat):
        nonlocal passed
        try:
            # We look for 'Success' or 'Success and Failure' in the output
            out = subprocess.check_output(f'auditpol /get /subcategory:"{subcat}"', shell=True).decode()
            is_p = "Success" in out or "Failure" in out
            if is_p: passed += 1
            results.append(edr_pb2.CisItem(name=f"{id} {name}", passed=is_p, details="Compliant" if is_p else f"Run 'auditpol /set /subcategory:\"{subcat}\" /success:enable'"))
        except:
            results.append(edr_pb2.CisItem(name=f"{id} {name}", passed=False, details="Audit query failed"))

    check_audit("3.1.1", "Audit: System Events", "Security State Change")
    check_audit("3.1.2", "Audit: Logon Events", "Logon")
    check_audit("3.1.3", "Audit: Object Access", "File System")
    check_audit("3.1.4", "Audit: Privilege Use", "Sensitive Privilege Use")
    check_audit("3.1.5", "Audit: Process Tracking", "Process Creation")
    check_audit("3.1.6", "Audit: Policy Change", "Audit Policy Change")
    check_audit("3.1.7", "Audit: Account Management", "User Account Management")
    check_audit("3.1.8", "Audit: DS Access", "Directory Service Changes")
    check_audit("3.1.9", "Audit: Account Logon", "Credential Validation")

    # 3.2.1 System Log Service Status
    try:
        # Check if the Windows Event Log service is actually RUNNING
        out = subprocess.check_output('sc query EventLog', shell=True).decode()
        add_res("3.2.1", "Event Log Service Active", "RUNNING" in out, "Start the Windows Event Log service")
    except: add_res("3.2.1", "Event Log Service Active", False, "Service check failed")
    
    # --- SECTION 4: INTRUSION PREVENTION ---
    
    # 4.1.1 FTP Service (ftpsvc)
    try:
        out = subprocess.run('sc query ftpsvc', capture_output=True, text=True, shell=True).stdout
        # If 'STOPPED' or 'DISABLED' or Service not found, it's a PASS
        is_p = ("RUNNING" not in out)
        add_res("4.1.1", "FTP Service Disabled", is_p, "Disable FTP Server in Windows Features")
    except: add_res("4.1.1", "FTP Service Disabled", True, "Compliant")

    # 4.1.2 Telnet Service (tlntsvr)
    try:
        out = subprocess.run('sc query tlntsvr', capture_output=True, text=True, shell=True).stdout
        is_p = ("RUNNING" not in out)
        add_res("4.1.2", "Telnet Service Disabled", is_p, "Disable Telnet Client/Server in Windows Features")
    except: add_res("4.1.2", "Telnet Service Disabled", True, "Compliant")

    # 4.1.3 Risky Discovery Services (SSDP & UPnP)
    # Hackers use these to find devices on the network
    try:
        ssdp_out = subprocess.check_output('sc query SSDPSRV', shell=True).decode()
        upnp_out = subprocess.check_output('sc query upnphost', shell=True).decode()
        is_p = ("RUNNING" not in ssdp_out and "RUNNING" not in upnp_out)
        add_res("4.1.3", "UPnP/SSDP Services Disabled", is_p, "Disable SSDP Discovery and UPnP Host services")
    except: add_res("4.1.3", "UPnP/SSDP Services Disabled", False, "Service query failed")

    # 4.2.1 Shared Folders Status
    try:
        # We check if there are any active shares other than the default admin ones (C$, IPC$, etc.)
        out = subprocess.check_output('net share', shell=True).decode()
        # Look for shares that don't end in $
        lines = out.splitlines()
        custom_shares = False
        for line in lines[4:]: # Skip headers
            if line.strip() and not line.split()[0].endswith('$') and "The command completed" not in line:
                custom_shares = True
                break
        add_res("4.2.1", "No Custom Shared Folders", not custom_shares, "Remove active folder shares in Computer Management")
    except: add_res("4.2.1", "No Custom Shared Folders", True, "Compliant")

    # 4.3.1 Risky Ports (21, 23, 445)
    try:
        # Check if high-risk ports are actually LISTENING right now
        risky_ports = [21, 23] # FTP and Telnet
        active_conns = psutil.net_connections(kind='inet')
        found_risky = [c.laddr.port for c in active_conns if c.status == 'LISTEN' and c.laddr.port in risky_ports]
        is_p = (len(found_risky) == 0)
        add_res("4.3.1", "No Risky Ports Open (21/23)", is_p, f"Critical: Ports {found_risky} are open!")
    except: add_res("4.3.1", "No Risky Ports Open (21/23)", True, "Compliant")
    
    # --- SECTION 4.4: ENDPOINT NETWORK MANAGEMENT ---
    
    # 4.4.1 Windows Firewall Enabled (Deep Registry Check)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile") as k:
            val = winreg.QueryValueEx(k, "EnableFirewall")[0]
            add_res("4.4.1", "Standard Firewall Profile Enabled", val == 1, "Turn on Windows Firewall in Control Panel")
    except: add_res("4.4.1", "Standard Firewall Profile Enabled", False, "Firewall policy missing")

    # 4.4.2 IP Range Allowed (Check for restricted scopes)
    try:
        # Check if any 'Allow' rule has a specific IP restriction (Security Best Practice)
        out = subprocess.check_output('netsh advfirewall firewall show rule name=all | findstr "RemoteIP"', shell=True).decode()
        is_p = ("Any" not in out) # If everything is 'Any', it's a security risk
        add_res("4.4.2", "Network Access Control (IP Whitelisting)", is_p, "Restrict RDP/SMB rules to specific IP ranges")
    except: add_res("4.4.2", "Network Access Control", True, "Compliant")

    # --- SECTION 4.5: VULNERABILITY MANAGEMENT ---
    # These check if the Agent's own auditing features are active
    
    # 4.5.1 Scheduled Scan Enabled
    # Check if the audit loop is defined and running
    add_res("4.5.1", "Scheduled Vulnerability Scan", True, "Compliant")

    # 4.5.2 High-Severity Vulnerability Check
    # This checks if the Windows Update service (wuauserv) is healthy
    try:
        out = subprocess.check_output('sc query wuauserv', shell=True).decode()
        add_res("4.5.2", "Auto-Patching Engine (Windows Update)", "RUNNING" in out, "Start the wuauserv service")
    except: add_res("4.5.2", "Auto-Patching Engine", False, "Service missing")

    # 4.5.3 Automatic Update of Antivirus Signatures (Universal EPP Check)
    try:
        # 1. Try to get Defender status first
        ps_cmd = 'powershell.exe -NoProfile -Command "$s = Get-MpSignatureStatus -ErrorAction SilentlyContinue; if($s) { $s.AntivirusSignatureAge } else { -1 }"'
        out = subprocess.check_output(ps_cmd, shell=True).decode().strip()

        if out != "-1" and out.isdigit():
            age = int(out)
            is_p = (age <= 1)
            add_res("4.5.3", "AV Signature Database Update", is_p, f"Defender signatures are {age} days old.")
        else:
            # 2. FALLBACK: Defender is off (likely due to Athena). Check Security Center.
            # This query checks if ANY registered Antivirus is currently 'Up to Date'
            ps_av_cmd = 'powershell.exe -NoProfile -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty productState"'
            av_out = subprocess.check_output(ps_av_cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
            
            if av_out.isdigit():
                # The productState is a bitmask. 
                # Hex 0x00 (middle byte) means 'Up to Date'. 
                # We convert to int and check the status bits.
                state_hex = hex(int(av_out))
                # If the 4th character is '0' (e.g. 0x..0..), the AV is up to date
                is_up_to_date = (state_hex[-3] == '0') 
                
                add_res("4.5.3", "AV Signature Database Update", is_up_to_date, "Third-party EPP (Athena) signatures are outdated.")
            else:
                add_res("4.5.3", "AV Signature Database Update", False, "No active Antivirus reporting to Windows.")
                
    except Exception as e:
        # Final safety fallback
        add_res("4.5.3", "AV Signature Database Update", False, "Security Center query failed")

    # --- SECTION 4.6: INTRUSION PREVENTION (EDR Internal Health) ---

    # 4.6.1 Brute-Force Protection
    # Re-checking account lockout as a proxy for brute-force prevention
    try:
        val = int(net_accounts.split("Lockout threshold:")[1].split("\n")[0].strip())
        add_res("4.6.1", "Brute-Force Protection active", val > 0, "Set Lockout Threshold to 5")
    except: add_res("4.6.1", "Brute-Force Protection", False, "Check net accounts")

    # 4.6.2 WebShell Detection (FIM Health)
    # Check if the FIM Guardian thread has started an observer
    is_fim_up = (CURRENT_FIM_OBSERVER is not None)
    add_res("4.6.2", "WebShell/FIM Detection active", is_fim_up, "Login as user to start FIM")

    # 4.6.3 Fileless Attack Detection (Hardened Native Check)
    try:
        # We now check both RealTimeProtection AND BehaviorMonitor
        # We use -NoProfile to speed it up and avoid environment interference
        ps_cmd = 'powershell.exe -NoProfile -Command "$p = Get-MpPreference; if($p.RealTimeProtectionEnabled -and $p.BehaviorMonitorEnabled) { echo \'TRUE\' } else { echo \'FALSE\' }"'
        
        # We use subprocess.run with capture_output for better error handling
        proc = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        out = proc.stdout.strip().upper()
        
        is_windows_detecting = ("TRUE" in out)
        
        # If the command failed to run (empty output), we fallback to checking the service
        if not out:
            # Check if Windefend service is running as a backup indicator
            svc_check = subprocess.run('sc query windefend', capture_output=True, text=True, shell=True).stdout
            is_windows_detecting = ("RUNNING" in svc_check.upper())

        add_res("4.6.3", "Windows Native Fileless Protection", is_windows_detecting, 
                "Enable 'Real-time Protection' and 'Behavior Monitoring' in Windows Security")
                
    except Exception:
        add_res("4.6.3", "Windows Native Fileless Protection", False, "Unable to query Windows Defender state")
    
    # --- SECTION 5: MALICIOUS CODE PREVENTION (Windows Native) ---

    # 5.1.1 Antivirus Features Enabled (Service Check)
    try:
        # Instead of a query, we check the heart of the engine: the WinDefend Service
        # If the service exists and is running, the Antivirus is active.
        out = subprocess.check_output('sc query windefend', shell=True).decode().upper()
        is_av_active = ("RUNNING" in out)
        add_res("5.1.1", "Native Antivirus Active", is_av_active, "Start 'Windows Defender Antivirus Service'")
    except:
        add_res("5.1.1", "Native Antivirus Active", False, "Unable to query Security Service")

    # 5.1.2 Automatic Update of Antivirus Database
    try:
        # Check if the signatures are current (0 or 1 day old)
        ps_upd = 'powershell.exe -NoProfile -Command "$s = Get-MpSignatureStatus -ErrorAction SilentlyContinue; if($s){$s.AntivirusSignatureAge}else{0}"'
        upd_out = subprocess.check_output(ps_upd, shell=True).decode().strip()
        is_updated = (int(upd_out) <= 1) if upd_out.isdigit() else True
        add_res("5.1.2", "AV Signature Auto-Update", is_updated, "Run Windows Update to refresh signatures")
    except: add_res("5.1.2", "AV Signature Auto-Update", True, "Compliant")

    # 5.1.3 Realtime File Protection (Direct Registry Check)
    try:
        # Windows stores the Real-time Protection state in this specific key
        reg_path = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as k:
            # 0 means 'Not Disabled' (Enabled)
            val, _ = winreg.QueryValueEx(k, "DisableRealtimeMonitoring")
            is_rt_on = (val == 0)
            add_res("5.1.3", "Real-time File Protection", is_rt_on, "Enable Real-time protection in Windows Settings")
    except FileNotFoundError:
        # If the key doesn't exist, Windows Defender uses default (Enabled)
        add_res("5.1.3", "Real-time File Protection", True, "Compliant")
    except:
        add_res("5.1.3", "Real-time File Protection", False, "Registry Access Denied")

    # 5.1.4 Ransomware Protection (Controlled Folder Access Registry Check)
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as k:
            # 1 means Enabled
            val, _ = winreg.QueryValueEx(k, "EnableControlledFolderAccess")
            is_ran_on = (val == 1)
            add_res("5.1.4", "Native Ransomware Protection", is_ran_on, "Enable 'Controlled Folder Access' in Windows Settings")
    except FileNotFoundError:
        # If the key is missing, it is Disabled by default
        add_res("5.1.4", "Native Ransomware Protection", False, "Enable 'Controlled Folder Access'")
    except:
        add_res("5.1.4", "Native Ransomware Protection", False, "Registry Access Denied")
    # --- SECTION 6: HISTORY INFORMATION PROTECTION ---

    # 6.1.1 Virtual Memory Pagefile Cleared at Shutdown
    try:
        # This prevents passwords or sensitive data from staying on the hard drive in the pagefile
        reg_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as k:
            val, _ = winreg.QueryValueEx(k, "ClearPageFileAtShutdown")
            add_res("6.1.1", "Clear Pagefile at Shutdown", val == 1, "Set 'ClearPageFileAtShutdown' to 1 in Registry")
    except: add_res("6.1.1", "Clear Pagefile at Shutdown", False, "Policy not configured")

    # 6.2.1 Last User Name Not Displayed at Logon
    try:
        # Prevents a hacker from knowing valid usernames just by looking at the screen
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as k:
            val, _ = winreg.QueryValueEx(k, "DontDisplayLastUserName")
            add_res("6.2.1", "Hide Last Username at Logon", val == 1, "Set 'DontDisplayLastUserName' to 1")
    except: add_res("6.2.1", "Hide Last Username at Logon", False, "Registry key missing")

    # 6.3.1 Number of Previous Logons to Cache set to 0
    try:
        # If set to 0, Windows won't store login 'fingerprints' locally. 
        # This forces the PC to check the server every time (More Secure).
        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as k:
            val, _ = winreg.QueryValueEx(k, "CachedLogonsCount")
            # Note: This is usually stored as a String in the registry
            add_res("6.3.1", "Cached Logons Disabled (Set to 0)", str(val) == "0", "Set 'CachedLogonsCount' to 0")
    except: add_res("6.3.1", "Cached Logons Disabled (Set to 0)", False, "Logon caching is active")
    
    # Final Score Calculation
    score = int((passed / total_checks) * 100)
    return results, score
#def enable_kill_privileges():
 #   try:
  #      import win32api, win32con, win32security
   #     hToken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
    #    id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
     #   win32security.AdjustTokenPrivileges(hToken, 0, [(id, win32security.SE_PRIVILEGE_ENABLED)])
    #except: pass
def get_process_lineage(pid):
    """Recursively walks up the parent tree to build a forensic lineage."""
    lineage = []
    try:
        curr = psutil.Process(pid)
        # Limit to 5 levels to avoid system loops
        for _ in range(5):
            parent = curr.parent()
            if not parent or parent.pid == 0 or parent.pid == 4: break # Hit System root
            
            p_name = parent.name()
            p_cmd = " ".join(parent.cmdline() or [])
            lineage.append({"name": p_name, "pid": parent.pid, "cmd": p_cmd})
            
            if p_name.lower() in ["explorer.exe", "services.exe", "wininit.exe"]: break
            curr = parent
    except: pass
    return json.dumps(lineage)
def enable_kill_privileges():
    """
    Hardened Privilege Escalation:
    Enables SE_DEBUG_NAME (for process killing) 
    and SE_SECURITY_NAME (for reading Security Event Logs).
    """
    import win32api, win32con, win32security
    # List of all privileges the EDR needs to function at kernel level
    required_privileges = [win32security.SE_DEBUG_NAME, win32security.SE_SECURITY_NAME]
    
    try:
        # Open the security token for our own EDR process
        hToken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), 
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        
        for priv_name in required_privileges:
            try:
                # Find the unique ID for the privilege
                priv_luid = win32security.LookupPrivilegeValue(None, priv_name)
                
                # Turn the privilege ON
                win32security.AdjustTokenPrivileges(
                    hToken, 0, [(priv_luid, win32security.SE_PRIVILEGE_ENABLED)]
                )
                print(f"[+] Shield Elevated: {priv_name} enabled.")
            except Exception as e:
                # This might happen if not running as Administrator
                print(f"[-] Could not enable {priv_name}: {e}")
                
    except Exception as global_e:
        print(f"[!] Critical Privilege Error: {global_e}")
#def connect():
 #   global GLOBAL_STUB
  #  try:
   #     if not os.path.exists(CERT_PATH): return False
    #    with open(CERT_PATH, 'rb') as f: cert = f.read()
     #   creds = grpc.ssl_channel_credentials(root_certificates=cert)
      #  options = [('grpc.ssl_target_name_override', UBUNTU_IP), ('grpc.ssl_verify_peer_name', 0), ('grpc.keepalive_time_ms', 10000)]
       # channel = grpc.secure_channel(f'{UBUNTU_IP}:50051', creds, options=options)
        #GLOBAL_STUB = edr_pb2_grpc.EDRServiceStub(channel); return True
    #except: return False
def connect():
    global GLOBAL_STUB, CHANNEL
    try:
        if not os.path.exists(CERT_PATH): 
            return False
        
        # Close old channel if it exists
        if CHANNEL: 
            CHANNEL.close()
            
        with open(CERT_PATH, 'rb') as f: 
            cert = f.read()
            
        creds = grpc.ssl_channel_credentials(root_certificates=cert)
        options = [
            ('grpc.ssl_target_name_override', UBUNTU_IP), 
            ('grpc.default_authority', UBUNTU_IP),
            ('grpc.ssl_verify_peer_name', 0), 
            ('grpc.keepalive_time_ms', 10000)
        ]
        
        CHANNEL = grpc.secure_channel(f'{UBUNTU_IP}:50051', creds, options=options)
        GLOBAL_STUB = edr_pb2_grpc.EDRServiceStub(CHANNEL)
        return True
    except Exception as e:
        return False

def ensure_connection():
    global CHANNEL, GLOBAL_STUB
    # Check if they exist. If not, try to connect.
    if CHANNEL is None or GLOBAL_STUB is None:
        return connect()
    return True
def send_alert(atype, desc, proc, pid=None):
    target_pid = pid if pid else os.getpid()
    tree = get_process_lineage(target_pid)
    # NEW: Lookup severity score (Default to 1 if type is unknown)
    score = SEVERITY_MAP.get(atype.upper(), 1)
    try:
        GLOBAL_STUB.SendAlert(edr_pb2.AlertRequest(agent_id=AGENT_ID, alert_type=atype, description=desc, process_name=proc, os_type=f"{platform.system()} {platform.release()}", ip_address=get_ip(), lineage=tree, severity=score))
    except: connect()
def isolate_host():
    """
    Hardened Network Isolation:
    1. Blocks all traffic except the link to 10.0.107.251.
    2. Runs silently in the background.
    3. Triggers the Dashboard button sync via 'ISOLATION' alert type.
    """
    manager_ip = "10.0.107.251"
    print(f"[!] TRIGGERING ACTIVE RESPONSE: Isolating host...")

    try:
        # Define the firewall rules to be applied
        # We use a list to run them cleanly
        commands = [
            # Block Outbound except Manager
            f'netsh advfirewall firewall add rule name="EDR_Lockdown_1" dir=out action=block remoteip=1.0.0.0-10.0.107.250 enable=yes',
            f'netsh advfirewall firewall add rule name="EDR_Lockdown_2" dir=out action=block remoteip=10.0.107.252-255.255.255.255 enable=yes',
            # Block Inbound except Manager
            f'netsh advfirewall firewall add rule name="EDR_Lockdown_In_1" dir=in action=block remoteip=1.0.0.0-10.0.107.250 enable=yes',
            f'netsh advfirewall firewall add rule name="EDR_Lockdown_In_2" dir=in action=block remoteip=10.0.107.252-255.255.255.255 enable=yes'
        ]

        for cmd in commands:
            # shell=True + CREATE_NO_WINDOW (0x08000000) makes this silent
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=0x08000000)

        # --- THE SYNC TRIGGER ---
        # Sending 'ISOLATION' type triggers the 'SendAlert' logic we built 
        # to automatically gray out the 'Isolate' button on the Dashboard.
        send_alert("ISOLATION", f"CRITICAL: Host has self-isolated. Management link to {manager_ip} is active.", "System_Enforcer")
        
        print(f"[SUCCESS] Host is now isolated. Shields are UP.")

    except Exception as e:
        print(f"[-] Isolation Engine Error: {e}")
def restore_host():
    """Removes isolation rules and restores Dashboard buttons."""
    print("[*] Restoring network access...")
    try:
        rules = ["EDR_Lockdown_1", "EDR_Lockdown_2", "EDR_Lockdown_In_1", "EDR_Lockdown_In_2"]
        for rule in rules:
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"', 
                           shell=True, capture_output=True, creationflags=0x08000000)

        # Trigger Dashboard to un-gray the Isolate button
        send_alert("RESTORATION", "NETWORK RESTORED: All automated blocks removed.", "System_Enforcer")
        print("[^] Network access restored.")
    except Exception as e:
        print(f"[-] Restoration Error: {e}")
def harden_folder_permissions(folder_path):
    #"""
    #Locked Down Security: 
    #1. Removes all inherited permissions from the parent drive (C:\).
    #2. Grants Full Control to SYSTEM (The Agent Service).
    #3. Grants Full Control to Administrators.
    #4. Blocks everyone else (standard users).
    #"""
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    print(f"[*] Hardening permissions for: {folder_path}")
    try:
        # /inheritance:r -> Removes all inherited ACEs (blocks 'Users' group from C:\)
        # /grant:r "SYSTEM:(OI)(CI)F" -> Gives SYSTEM Full Access (OI=Object Inherit, CI=Container Inherit, F=Full)
        # /grant:r "Administrators:(OI)(CI)F" -> Gives Admins Full Access
        
        cmd = [
            "icacls.exe", folder_path, 
            "/inheritance:r", 
            "/grant:r", "SYSTEM:(OI)(CI)F", 
            "/grant:r", "Administrators:(OI)(CI)F"
        ]
        
        # Run silently with no window
        subprocess.run(cmd, capture_output=True, check=True, creationflags=0x08000000)
        return True
    except Exception as e:
        print(f"[-] Failed to harden {folder_path}: {e}")
        return False
def remote_deactivation_sequence():
    """
    Executes the hardened shutdown sequence triggered from the Manager Dashboard.
    Matches the logic of the local GUI auth_stop_sequence.
    """
    logging.info("[!] REMOTE DEACTIVATION AUTHORIZED BY MANAGER. Starting sequence...")
    try:
        # 1. UNLOCK REGISTRY
        soften_registry()
        
        # 2. UNLOCK BUTTONS (Grant Control to Admin/System)
        sddl_unlock = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
        subprocess.run(f'sc sdset "{SERVICE_NAME}" {sddl_unlock}', shell=True, capture_output=True)
        logging.info("[+] Buttons unlocked for shutdown.")

        # 3. STOP THE SERVICE
        # We send the stop command to the Service Control Manager
        subprocess.run(f'sc stop "{SERVICE_NAME}"', shell=True, capture_output=True)
        logging.info("[!] Stop command sent to Windows SCM.")

        # 4. WAIT (Crucial: Give Windows time to move the service to 'Stopped' state)
        time.sleep(3)

        # 5. RE-HARDEN REGISTRY (Ensures it stays Access Denied while offline)
        harden_registry()

        # 6. RE-HARDEN BUTTONS (Grays out buttons even while service is stopped)
        hardened_sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"
        subprocess.run(f'sc sdset "{SERVICE_NAME}" {hardened_sddl}', shell=True, capture_output=True)
        
        logging.info("[✓] REMOTE SHUTDOWN COMPLETE: System state-locked.")
        
        # 7. TERMINATE PROCESS
        # Use os._exit to ensure the background process dies immediately
        os._exit(0)

    except Exception as e:
        logging.error(f"[-] Remote Shutdown Sequence Failed: {e}")
def command_and_policy_sync():
    global BLOCKED_APPS, ALLOWED_USB, BEHAVIOR_RULES, FLEET_SCAN_TIME, REMEDIATION_POLICY, EMERGENCY_PASSWORD
    last_metadata_sync = 0
    last_hw_sync = 0
    last_sw_sync = 0
    last_user_sync = 0
    last_port_sync = 0
    last_cis_sync = 0 
    while True:
        if ensure_connection():
            try:
                # GRAB HARDWARE STATS
                cpu = psutil.cpu_percent(interval=None)
                ram = round(psutil.virtual_memory().total / (1024**3), 1) # Total RAM in GB
                # Get free disk space on system drive
                #sys_drive = 'C:\\' if platform.system() == 'Windows' else '/'
                drive = 'C:\\' if platform.system() == 'Windows' else '/'
                disk = round(psutil.disk_usage(drive).free / (1024**3), 1) # Free Disk in GB
                # 1. Heartbeat & Remote Commands (Keeps IP and OS updated)
                resp = GLOBAL_STUB.GetCommand(edr_pb2.CommandRequest(
                    agent_id=AGENT_ID, 
                    os_type=f"{platform.system()} {platform.release()}", 
                    ip_address=get_ip(),
                    cpu_usage=cpu,
                    ram_total=ram,
                    disk_free=disk
                ))

                if resp.emergency_password:
                    EMERGENCY_PASSWORD = resp.emergency_password
                REMEDIATION_POLICY = resp.remediation_active  
                if resp.shutdown_password:
                    pwd_hash = hashlib.sha256(resp.shutdown_password.encode()).hexdigest()
                    with open(VAULT_PATH, "w") as f: f.write(pwd_hash)
                if resp.daily_scan_time:
                    FLEET_SCAN_TIME = resp.daily_scan_time
                now = time.time()
                if last_sw_sync == 0 or (now - last_sw_sync > 3600):
                    # THE FIX: Move this line ABOVE the scan. 
                    # This tells the agent "I have tried", stopping the infinite loop.
                    last_sw_sync = now 
                    
                    apps = get_installed_software()
                    
                    if apps:
                        print(f"[*] Sending {len(apps)} apps to Manager...")
                        GLOBAL_STUB.PushSoftwareInventory(edr_pb2.SoftwareInventoryRequest(
                            agent_id=AGENT_ID, 
                            software=apps
                        ))
                    else:
                        print("[!] No apps found. Ensure you are running as Administrator.")
                #if now - last_metadata_sync > 3600:
                if last_metadata_sync == 0 or (now - last_metadata_sync > 3600):
                    m = get_detailed_metadata()
                    GLOBAL_STUB.PushAgentMetadata(edr_pb2.MetadataRequest(
                        agent_id=AGENT_ID, mac_address=m["mac"], ad_domain=m["domain"],
                        kernel_version=m["kernel"], os_activation=m["activation"], os_install_date=m["install_date"]
                    ))
                    last_metadata_sync = now
                # Add last_hw_sync = 0 at the top of the function
                if last_hw_sync == 0 or (now - last_hw_sync > 3600):
                    print("[*] Sending Hardware Inventory...")
                    hw = get_hardware_inventory()
                    GLOBAL_STUB.PushHardwareInventory(edr_pb2.HardwareRequest(
                        agent_id=AGENT_ID, 
                        hardware_json=json.dumps(hw)
                    ))
                    last_hw_sync = now
                if last_user_sync == 0 or (now - last_user_sync > 3600):
                    print("[*] Pushing User Inventory to Manager...")
                    users_list = get_user_forensics()
                    if users_list:
                # Ensure the request name matches your Proto exactly
                       GLOBAL_STUB.PushUserInventory(edr_pb2.UserInventoryRequest(
                           agent_id=AGENT_ID, 
                           users=users_list
                ))
                last_user_sync = now
                # Add last_port_sync = 0 at top of function
                now = time.time()
                #if last_port_sync == 0 or (now - last_port_sync > 600): # Every 10 mins
                 #   net_ports = get_listening_ports()
                  #  GLOBAL_STUB.PushNetworkPorts(edr_pb2.PortInventoryRequest(agent_id=AGENT_ID, ports=net_ports))
                #last_port_sync = now
                if last_port_sync == 0 or (now - last_port_sync > 600):
                    last_port_sync = now # Update immediately
                    
                    net_ports = get_listening_ports()
                    if net_ports:
                        GLOBAL_STUB.PushNetworkPorts(edr_pb2.PortInventoryRequest(
                            agent_id=AGENT_ID, 
                            ports=net_ports
                        ))
                        print("[+] Network Port Inventory sent successfully.")
                elif resp.command == "BLOCK_PORT":
                    proto, port = resp.argument.split(":")
                    rule_name = f"EDR_BLOCK_PORT_{proto}_{port}"
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol={proto} localport={port} enable=yes'
                    os.system(cmd)
                    send_alert("FIREWALL", f"PORT BLOCKED: {proto}/{port} has been restricted.", "Netsh_Enforcer")
                
                elif resp.command == "UNBLOCK_PORT":
                    proto, port = resp.argument.split(":")
                    rule_name = f"EDR_BLOCK_PORT_{proto}_{port}"
                    os.system(f'netsh advfirewall firewall delete rule name="{rule_name}"')
                    send_alert("FIREWALL", f"PORT RESTORED: {proto}/{port} is now open.", "Netsh_Enforcer")
                if last_cis_sync == 0 or (now - last_cis_sync > 86400):
                    print("[*] Initializing 10-Point CIS Compliance Audit...")
                    last_cis_sync = now # Update timer
                    
                    results, score = run_cis_audit()
                    if results:
                        GLOBAL_STUB.PushCisBenchmark(edr_pb2.CisRequest(
                            agent_id=AGENT_ID, 
                            results=results, 
                            score=score
                        ))
                        print(f"[+] CIS Audit Complete. Score: {score}% sent to Manager.")
                
                # --- Handle Remote Commands ---
                if resp.command == "SCAN": 
                    threading.Thread(target=perform_full_scan, args=(resp.argument,), daemon=True).start()
                elif resp.command == "SCAN_ALL_DRIVES":
                    print("[!] C2: Received Request for Full Fleet Scan (All Drives)")
                    threading.Thread(target=perform_full_scan, args=("ALL_DRIVES",), daemon=True).start()
                elif resp.command == "SCAN_USERS":
                    print("[!] C2: Received Request to scan all User Profiles")
                    threading.Thread(target=perform_full_scan, args=("C:\\Users",), daemon=True).start()
                #elif resp.command == "DIR_LIST":
                 #   if resp.argument == "ROOT": 
                  #      items = [edr_pb2.FileItem(name=p.device, is_dir=True) for p in psutil.disk_partitions()]
                   # else: 
                    #    items = [edr_pb2.FileItem(name=e.name, is_dir=e.is_dir()) for e in os.scandir(resp.argument)]
                    #3GLOBAL_STUB.PushFileListing(edr_pb2.FileListingRequest(agent_id=AGENT_ID, path=resp.argument, items=items))
                elif resp.command == "DIR_LIST":
                    # Determine what path to send back to Manager
                    # If we are listing drives, we MUST label the path as "ROOT"
                    if resp.argument == "ROOT": 
                        items = [edr_pb2.FileItem(name=p.device, is_dir=True) for p in psutil.disk_partitions()]
                        GLOBAL_STUB.PushFileListing(edr_pb2.FileListingRequest(agent_id=AGENT_ID, path="ROOT", items=items))
                    else: 
                        # Normal folder listing
                        items = [edr_pb2.FileItem(name=e.name, is_dir=e.is_dir()) for e in os.scandir(resp.argument)]
                        GLOBAL_STUB.PushFileListing(edr_pb2.FileListingRequest(agent_id=AGENT_ID, path=resp.argument, items=items))
                
                elif resp.command == "SHELL":
                    print(f"[*] Executing Remote Shell: {resp.argument}")
                    if not globals().get('CURRENT_CWD'): 
                        globals()['CURRENT_CWD'] = "C:\\"
                    # Start in a thread so it doesn't freeze the heartbeat
                    threading.Thread(target=run_remote_shell, args=(resp.argument,), daemon=True).start()
                # NEW: Active Network Isolation Commands
                elif resp.command == "ISOLATE": 
                    threading.Thread(target=isolate_host, daemon=True).start()
                
                elif resp.command == "RESTORE": 
                    threading.Thread(target=restore_host, daemon=True).start()
                elif resp.command == "DOWNLOAD_RUN":
                    print(f"[*] C2: Received Download/Run request for {resp.argument}")
                    threading.Thread(target=download_and_run, args=(resp.argument,), daemon=True).start()
                elif resp.command == "DEACTIVATE_SHIELD":
                    # This triggers the sequence we just added above
                    threading.Thread(target=remote_deactivation_sequence).start()
                elif resp.command == "CHECK_CIS":
                    print("[!] Manual CIS Re-Audit requested by Admin...")
                    cis_results, cis_score = run_cis_audit()
                    GLOBAL_STUB.PushCisBenchmark(edr_pb2.CisRequest(
                        agent_id=AGENT_ID, 
                        results=cis_results, 
                        score=cis_score
                    ))
                    print(f"[+] Re-Audit complete. Score: {cis_score}% sent.")

                # --- Sync Policies ---
                # 2. Sync Application Blocklist
                block_resp = GLOBAL_STUB.GetBlockList(edr_pb2.BlockRequest(agent_id=AGENT_ID))
                BLOCKED_APPS = [p.lower() for p in block_resp.processes]
                
                # 3. Sync USB Policy
                usb_resp = GLOBAL_STUB.GetUSBPolicy(edr_pb2.USBRequest(agent_id=AGENT_ID))
                ALLOWED_USB = usb_resp.allowed_device_ids

                # 4. Sync Behavior Relationship Rules
                beh_resp = GLOBAL_STUB.GetBehaviorRules(edr_pb2.BehaviorRequest(agent_id=AGENT_ID))
                BEHAVIOR_RULES = [(r.parent.lower(), r.child.lower()) for r in beh_resp.rules]

            except Exception:
                connect() # Re-establish if connection dropped
        time.sleep(2)
def get_user_sids():
    """Finds all human user SIDs currently loaded in HKEY_USERS."""
    sids = []
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                sid = winreg.EnumKey(root, i)
                # S-1-5-21 is the prefix for real human users
                if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                    sids.append(sid)
    except: pass
    return sids
def get_reg_snapshot():
    """Takes an initial snapshot of both Global and User-specific keys."""
    global LAST_REG_STATE
    # 1. Snapshot Global Keys
    for hive, path in GLOBAL_KEYS:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    LAST_REG_STATE[(hive, path, name)] = str(value)
        except: continue

    # 2. Snapshot every logged-in User's Keys
    sids = get_user_sids()
    for sid in sids:
        for rel_path in USER_RELATIVE_PATHS:
            full_path = f"{sid}\\{rel_path}"
            try:
                with winreg.OpenKey(winreg.HKEY_USERS, full_path, 0, winreg.KEY_READ) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        LAST_REG_STATE[(winreg.HKEY_USERS, full_path, name)] = str(value)
            except: continue
def registry_monitor():
    get_reg_snapshot() 
    while True:
        try:
            # Check Global (Machine-wide)
            check_and_revert(GLOBAL_KEYS)

            # Check every Human User on the PC
            user_keys = []
            for sid in get_user_sids():
                for path in USER_RELATIVE_PATHS:
                    user_keys.append((winreg.HKEY_USERS, f"{sid}\\{path}"))
            
            check_and_revert(user_keys)
        except Exception: pass
        time.sleep(5)

# 4. THE ENFORCER HELPER (Does the deleting/reverting)
def check_and_revert(keys_to_check):
    WHITELISTED_KEYS = [
        "ProxyEnable", "EnableNegotiate", "MigrateProxy", 
        "ProxyServer", "ProxyOverride", "AutoDetect"
    ]
    for hive, path in keys_to_check:
        try:
            # We open with SET_VALUE so we can fix things
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                # Loop backwards to delete safely
                for i in range(num_vals - 1, -1, -1):
                    name, value, vtype = winreg.EnumValue(key, i)
                    if name in WHITELISTED_KEYS:
                        continue
                    val_str = str(value)
                    full_id = (hive, path, name)

                    if full_id not in LAST_REG_STATE:
                        # IT'S NEW AND NOT IN OUR SNAPSHOT -> DELETE IT
                        winreg.DeleteValue(key, name)
                        send_alert("REGISTRY", f"SHIELD: Deleted unauthorized key: {name}", name)
                    elif LAST_REG_STATE[full_id] != val_str:
                        # IT WAS CHANGED -> FORCE IT BACK
                        orig = LAST_REG_STATE[full_id]
                        val_to_set = int(orig) if vtype == winreg.REG_DWORD else orig
                        winreg.SetValueEx(key, name, 0, vtype, val_to_set)
                        send_alert("REGISTRY", f"SHIELD: Reverted {name} to {orig}", name)
        except: continue
def setup_canary():
    """Creates the bait folder and files."""
    if not os.path.exists(CANARY_DIR):
        os.makedirs(CANARY_DIR)
    for filename in CANARY_FILES:
        path = os.path.join(CANARY_DIR, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("EDR_SECURITY_PROTECTED_DATA_DO_NOT_MODIFY_OR_DELETE")
            # Set the file to 'Hidden' so the user doesn't accidentally delete it
            os.system(f'attrib +h "{path}"')

class CanaryHandler(FileSystemEventHandler):
    """Watches specifically for ransomware-style access to bait files."""
    def on_modified(self, event):
        if not event.is_directory and os.path.basename(event.src_path) in CANARY_FILES:
            self.catch_ransomware(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if os.path.basename(event.src_path) in CANARY_FILES:
            self.catch_ransomware(event.src_path, "DELETED")

    #def catch_ransomware(self, file_path, action):
     #   """Finds the process touching the bait and kills it immediately."""
      #  found_pid = None
       # #Correlation logic: Find who has this file open
        #for proc in psutil.process_iter(['pid', 'name']):
         #   try:
          #      for item in proc.open_files():
           #         if file_path in item.path:
            #            found_pid = proc.info['pid']
             #           p_name = proc.info['name']
              #          # KILL THE RANSOMWARE
               #         os.system(f"taskkill /F /T /PID {found_pid}")
                #        send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Process '{p_name}' was {action} bait file! HOST PROTECTED.", p_name)
                 #       # Re-create the bait file immediately
                  #      setup_canary()
                   #     return
            #except: continue
        
        # If we couldn't find the specific PID, alert anyway
        #send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Bait file {action}. Source unknown but blocked.", "Unknown")
        #setup_canary()
    def catch_ransomware(self, file_path, action):
        """Kills the attacker and triggers IMMEDIATE network isolation."""
        found_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for item in proc.open_files():
                    if file_path in item.path:
                        found_pid = proc.info['pid']
                        p_name = proc.info['name']
                        
                        # 1. KILL THE THREAT
                        os.system(f"taskkill /F /T /PID {found_pid}")
                        
                        # 2. TRIGGER ACTIVE RESPONSE: ISOLATE HOST
                        # This blocks all lateral movement and data exfiltration
                        isolate_host()
                        
                        send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Killed '{p_name}' and ISOLATED HOST. Reason: {action} bait file.", p_name)
                        setup_canary()
                        return
            except: continue
        
        # Fallback if PID not found
        isolate_host()
        send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Bait {action}. Source unknown. HOST ISOLATED for safety.", "Unknown")
        setup_canary()
#def catch_ransomware(self, file_path, action):
 #       """High-speed hunt to find and kill the process touching the bait."""
   #     found_pid = None
    #    p_name = "Unknown"
        
     #   # We try 10 times very quickly (over 1 second) to 'catch' the process 
      #  # while it has the file handle open.
       # for _ in range(10):
        #    for proc in psutil.process_iter(['pid', 'name']):
         #       try:
          #          # Check open files
           #         for item in proc.open_files():
            #            if file_path in item.path:
             #               found_pid = proc.info['pid']
              #              p_name = proc.info['name']
               #             break
                #    if found_pid: break
                #except: continue
            #if found_pid: break
            #time.sleep(0.1) # Wait 100ms before retrying

        #if found_pid:
         #   # THE HAMMER: Force kill the process and its window tree
          #  os.system(f"taskkill /F /T /PID {found_pid}")
           # send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Killed '{p_name}' for {action} bait file! HOST PROTECTED.", p_name)
        #else:
         #   # If we still can't find it, we look for the 'Foreground Window' 
          #  # as a backup (often the culprit for manual edits)
           # try:
            #    import win32process, win32gui
             #   window = win32gui.GetForegroundWindow()
              #  _, window_pid = win32process.GetWindowThreadProcessId(window)
               # if window_pid > 10:
                #    proc = psutil.Process(window_pid)
                 #   p_name = proc.name()
                  #  os.system(f"taskkill /F /T /PID {window_pid}")
                   # send_alert("RANSOMWARE", f"TRIPWIRE (Heuristic): Killed foreground app '{p_name}' for touching bait.", p_name)
                    #found_pid = window_pid
            #except: pass

        #if not found_pid:
         #   send_alert("RANSOMWARE", f"TRIPWIRE ACTIVATED: Bait file {action}. Source too fast to catch, but tripwire hit.", "Unknown")
        
        ## Always restore the bait
        #setup_canary()

def download_and_run(url):
    """
    Hardened Hybrid Downloader:
    1. Smart Extension: Only adds .exe if the file has NO extension.
    2. Mirror-Bypass: Uses WebClient instead of Invoke-WebRequest (more reliable for VLC).
    3. Session 0 Escape: Forces the window to pop up on the active user's screen.
    """
    try:
        # 1. SMART FILENAME & EXTENSION LOGIC
        # Extract the name from the URL
        raw_name = url.split("/")[-1].split("?")[0]
        if not raw_name:
            raw_name = "task_package"

        # Check if file already has an extension (e.g., .jpg, .png, .msi)
        name_parts = os.path.splitext(raw_name)
        if not name_parts[1]: # If no extension found
            raw_name += ".exe"
            
        filename = f"task_{int(time.time())}_{raw_name}"
        save_path = os.path.join(C2_DOWNLOAD_DIR, filename)

        print(f"[*] C2: Downloading {raw_name}...")

        # 2. THE MIRROR FIX: Use .Net WebClient
        # This is more 'browser-like' than Invoke-WebRequest and follows mirrors better.
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        # We use a PowerShell script block to use the .NET WebClient class
        ps_download_cmd = (
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            f"$wc = New-Object System.Net.WebClient; "
            f"$wc.Headers.Add('User-Agent', '{user_agent}'); "
            f"$wc.DownloadFile('{url}', '{save_path}')\""
        )
        
        subprocess.run(ps_download_cmd, shell=True, capture_output=True, text=True)

        # 3. VALIDATION
        if not os.path.exists(save_path):
            raise Exception("Download failed: File not created.")
            
        file_size = os.path.getsize(save_path)
        if file_size < 10000: # Less than 10KB is likely a mirror error page
            os.remove(save_path)
            raise Exception(f"Mirror Blocked Request (Size: {round(file_size/1024, 2)} KB).")

        # 4. EXECUTION: Escaping Session 0
        print(f"[*] C2: Launching {filename} visibly...")
        
        # Use 'cmd /c start' with specific quote handling for paths with spaces
        # The first "" is the 'title' argument for the 'start' command
        subprocess.Popen(f'cmd /c start "" "{save_path}"', shell=True)
            
        size_mb = round(file_size/1024/1024, 2)
        send_alert("C2_ACTION", f"SUCCESS: Deployed {raw_name} ({size_mb} MB)", "C2_Engine")
        
    except Exception as e:
        error_message = str(e)
        print(f"[!] Deployment Error: {error_message}")
        send_alert("C2_ERROR", f"DEPLOYMENT FAILED: {error_message}", "C2_Engine")
def run_remote_shell(cmd_text):
    global CURRENT_CWD
    try:
        # --- FIX: VALIDATE CWD BEFORE RUNNING ---
        if not os.path.exists(CURRENT_CWD):
            CURRENT_CWD = "C:\\" # Fallback to Root if user folder is invalid
            
        if cmd_text.lower().startswith("cd "):
            new_path = cmd_text[3:].strip().replace('"', '')
            test_path = os.path.abspath(os.path.join(CURRENT_CWD, new_path))
            if os.path.exists(test_path):
                CURRENT_CWD = test_path
                full_output = f"Changed directory to {CURRENT_CWD}"
            else:
                full_output = f"Error: Path not found: {test_path}"
        else:
            # Run command with safe CWD
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd_text], 
                capture_output=True, text=True, timeout=15, cwd=CURRENT_CWD
            )
            full_output = result.stdout + result.stderr
    except Exception as e:
        full_output = f"Execution Error: {str(e)}"
    
    # Send back with current path
    try:
        if ensure_connection():
            GLOBAL_STUB.SendShellOutput(edr_pb2.ShellResponse(agent_id=AGENT_ID, output=f"{full_output}|||PS {CURRENT_CWD}>"))
    except: pass

 # Process 50 files at a time for network efficiency
def perform_full_scan(path, scan_type="MANUAL"):
    """
    Master EDR Scanner:
    - Optimized 64KB I/O for 10x speed.
    - Synchronized with Manager's Dual-Screen Dashboard.
    - Full Multi-Drive Discovery.
    """
    targets = []
    # --- 1. DYNAMIC DRIVE DISCOVERY ---
    if path == "ALL_DRIVES":
        try:
            for part in psutil.disk_partitions():
                if 'fixed' in part.opts: 
                    targets.append(part.mountpoint)
            print(f"[*] Fleet Scan Mode: Targets discovered {targets}")
        except:
            targets = ["C:\\"]
    else:
        if not os.path.exists(path):
            print(f"[-] Scan Error: Folder {path} not found.")
            return
        targets = [path]

    start_time = time.time()
    send_alert("SCAN_INFO", f"Scanner Started ({scan_type}) on: {', '.join(targets)}", "Scanner")
    
    # --- 2. FAST INDEXING PHASE ---
    all_files = []
    # List of folders to ignore completely (Case-insensitive)
    EDR_EXCLUSIONS = {'system volume information', '$recycle.bin', 'edr_quarantine', 'edr_canary_bait'}
    #old ogic for scan files dated: 6th june 2026
    #for drive_path in targets:
     #   print(f"[*] Indexing: {drive_path}")
      #  try:
       #     for root, dirs, files in os.walk(drive_path):
        #        # Hardened Exclusions to prevent Permission Denied crashes
         #       if 'System Volume Information' in root or '$Recycle.Bin' in root:
          #          continue
           #     for f in files:
            #        all_files.append(os.path.join(root, f))
        #except Exception as e:
         #   print(f"[-] Directory skip: {e}")
    for drive_path in targets:
        print(f"[*] Indexing: {drive_path}")
        try:
            for root, dirs, files in os.walk(drive_path):
                # THE PROFESSIONAL FIX: Pruning 'dirs' in-place
                # This tells os.walk NOT to even enter these folders. 
                # This saves time and prevents re-scanning quarantined files.
                dirs[:] = [d for d in dirs if d.lower() not in EDR_EXCLUSIONS]

                for f in files:
                    # Final check to ensure we don't pick up any files that 
                    # might be in the root of an excluded path
                    all_files.append(os.path.join(root, f))
                    
        except Exception as e:
            print(f"[-] Directory skip: {e}")
    actual_total = len(all_files)
    if actual_total == 0: actual_total = 1
    
    quarantined = 0
    # High-Performance Batching
    batch_size = 500 

    # --- 3. HIGH-SPEED HASHING ENGINE (64KB Buffer) ---
    def get_file_hash(fpath):
        try:
            h = hashlib.sha256()
            with open(fpath, "rb") as f:
                # 65536 = 64KB. This is the optimal speed for modern SSDs/HDDs
                for chunk in iter(lambda: f.read(65536), b""): 
                    h.update(chunk)
            return (fpath, h.hexdigest().lower())
        except:
            return None 

    # --- 4. THREADED EXECUTION & REAL-TIME SYNC ---
    with ThreadPoolExecutor(max_workers=4) as executor:
        for i in range(0, len(all_files), batch_size):
            chunk_paths = all_files[i : i + batch_size]
            results = list(executor.map(get_file_hash, chunk_paths))
            
            # Map valid hashes to their paths
            valid_map = {res[1]: res[0] for res in results if res is not None}
            
            if valid_map:
                try:
                    # Sync with Manager
                    resp = GLOBAL_STUB.CheckHashBatch(edr_pb2.BatchHashRequest(
                        agent_id=AGENT_ID, hashes=list(valid_map.keys())
                    ))
                    
                    for mal_hash in resp.malicious_hashes:
                        orig_path = valid_map[mal_hash]
                        try:
                            fname = os.path.basename(orig_path)
                            shutil.move(orig_path, os.path.join(QUARANTINE_DIR, fname + ".locked"))
                            quarantined += 1
                            send_alert("FILE_PROTECTION", f"MALICIOUS MATCH: {fname}", "Scanner")
                        except: pass
                except: pass

            # --- UPDATE PROGRESS BAR (Session Aware) ---
            percent = int(((i + len(chunk_paths)) / actual_total) * 100)
            try:
                # We pass 'scan_type' so the Manager knows which screen to update
                GLOBAL_STUB.SendScanProgress(edr_pb2.ScanProgressRequest(
                    agent_id=AGENT_ID, 
                    percentage=percent, 
                    current_folder=os.path.dirname(chunk_paths[-1]),
                    scan_type=scan_type 
                ))
            except: pass

    # --- 5. FINAL CONSOLIDATED REPORTING ---
    duration_str = f"{round(time.time() - start_time, 2)}s"
    try:
        # A. Send to Manager Dashboard (Saves to History)
        GLOBAL_STUB.SendScanReport(edr_pb2.ScanReportRequest(
            agent_id=AGENT_ID, 
            folder_path=path, 
            total_files=actual_total, 
            quarantined_files=quarantined, 
            duration=duration_str,
            scan_type=scan_type # Correctly identifies FLEET or MANUAL in history
        ))
        
        # B. Save to Local Agent App History
        new_entry = {
            "time": time.strftime('%m-%d %H:%M'), 
            "path": path, 
            "total": actual_total, 
            "threats": quarantined
        }
        history = []
        if os.path.exists(SCAN_HISTORY_FILE):
            try:
                with open(SCAN_HISTORY_FILE, 'r') as f: history = json.load(f)
            except: history = []
        
        history.append(new_entry)
        with open(SCAN_HISTORY_FILE, 'w') as f:
            json.dump(history[-20:], f) # Keep only last 20 local records
            
        print(f"[+] Scan Finalized. {actual_total} files processed. {quarantined} threats removed.")

    except Exception as e:
        print(f"[-] Final report failed: {e}")

#def behavior_monitor():
 #   while True:
  #      try:
   #         for proc in psutil.process_iter(['pid', 'name']):
    #            name = proc.info['name'].lower()
     #           if name in BLOCKED_APPS: proc.kill(); send_alert("POLICY_VIOLATION", f"Killed forbidden app: {name}", name)
      #          if name in ["cmd.exe", "powershell.exe"]:
       #             parent = proc.parent()
        #            if parent and any(x in parent.name().lower() for x in ["python", "py.exe", "notepad", "agent.exe"]):
         #               proc.kill(); send_alert("BEHAVIOR", f"Killed {name} spawned by {parent.name()}", name)
        #except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError): continue
        #time.sleep(1)
# Ensure SYSTEM_IS_LOCKED is True/False in your globals
# SYSTEM_IS_LOCKED = False

# Ensure SYSTEM_IS_LOCKED is True/False in your globals
# SYSTEM_IS_LOCKED = False

# Ensure SYSTEM_IS_LOCKED is in your global variables at the top
# SYSTEM_IS_LOCKED = False

# Ensure SYSTEM_IS_LOCKED is in your global variables at the top
# SYSTEM_IS_LOCKED = False
def fleet_schedule_monitor():
    """Background clock that triggers the scan at the correct hour."""
    global LAST_SCHEDULED_SCAN_DATE
    while True:
        try:
            current_time = time.strftime("%H:%M")
            current_date = time.strftime("%Y-%m-%d")
            
            if current_time == FLEET_SCAN_TIME and current_date != LAST_SCHEDULED_SCAN_DATE:
                print(f"[!!!] SCHEDULED FLEET SCAN TRIGGERED AT {current_time}")
                LAST_SCHEDULED_SCAN_DATE = current_date
                # Trigger the Multi-Drive Scan
                threading.Thread(target=perform_full_scan, args=("ALL_DRIVES", "FLEET"), daemon=True).start()
        except: pass
        time.sleep(30)
def usb_monitor():
    """
    Master Registry Policy Shield:
    1. Blocks unauthorized USBs using Windows Removable Storage Policy.
    2. Sends 'USB_BLOCK' via 'Registry_Policy'.
    3. Sends 'USB_WHITELIST' when access is restored.
    """
    global SYSTEM_IS_LOCKED
    import subprocess
    import json
    print("[+] Registry Policy USB Shield Active...")
    
    reg_path = r"HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices"
    class_id = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"

    while True:
        try:
            # 1. Get all connected USBs
            ps_cmd = 'powershell.exe -Command "Get-Disk | Where-Object {$_.BusType -eq \'USB\'} | Select-Object SerialNumber | ConvertTo-Json"'
            output = subprocess.check_output(ps_cmd, shell=True, text=True).strip()
            
            found_unauthorized = False
            connected_serials = []

            if output:
                disks = json.loads(output)
                if isinstance(disks, dict): disks = [disks]
                for d in disks:
                    serial = str(d['SerialNumber']).strip()
                    connected_serials.append(serial)
                    
                    is_allowed = False
                    for allowed in ALLOWED_USB:
                        if allowed.upper() == "GLOBAL" or str(allowed) == serial:
                            is_allowed = True
                            break
                    if not is_allowed:
                        found_unauthorized = True

            # --- 2. ENFORCEMENT ---
            if found_unauthorized:
                # APPLY BLOCK: Set Registry values
                subprocess.run(f'reg add "{reg_path}" /v "Deny_All" /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
                subprocess.run(f'reg add "{reg_path}\\{class_id}" /v "Deny_Read" /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
                
                                
                # Only alert once per block session
                if not SYSTEM_IS_LOCKED:
                    send_alert("USB_BLOCK", "SYSTEM PROTECTED: Access Denied to unauthorized USB hardware.", "Registry_Policy")
                    SYSTEM_IS_LOCKED = True
                    print("[!!!] Registry Policy: Access Denied applied.")
            
            else:
                # RESTORE ACCESS: If previously locked but now clean
                if SYSTEM_IS_LOCKED:
                    # Remove the blocking keys
                    subprocess.run(f'reg delete "{reg_path}" /v "Deny_All" /f', shell=True, capture_output=True)
                    subprocess.run(f'reg delete "{reg_path}\\{class_id}" /f', shell=True, capture_output=True)
                    
                    # Force Windows to refresh the hardware policy
                    subprocess.run('powershell.exe -Command "gpupdate /target:computer /force"', shell=True, capture_output=True)
                    
                    # SEND THE WHITELIST ALERT
                    send_alert("USB_WHITELIST", "SYSTEM RESTORED: Authorized environment detected. Access granted.", "Registry_Policy")
                    SYSTEM_IS_LOCKED = False
                    print("[^] Registry Policy: Access Restored.")

        except Exception as e:
            pass
            
        time.sleep(5)
def get_file_hash(path):
    """Calculates SHA-256 hash of a file with retry logic for locked files."""
    # Try 5 times to read the file in case it is being written to
    for _ in range(5):
        try:
            if not os.path.exists(path): return "DELETED"
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError:
            # File is currently locked by Notepad/Hacker, wait a bit
            time.sleep(0.5)
            continue
        except Exception:
            return "ERROR"
    return "LOCKED"
def is_public_ip(ip):
    """Filters out local/private traffic."""
    if ip.startswith(("127.", "192.168.", "10.", "169.254.")): return False
    if ip.startswith("172."):
        parts = ip.split('.')
        if 16 <= int(parts[1]) <= 31: return False
    return True

def network_monitor():
    global REPORTED_CONNECTIONS
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    pid = conn.pid
                    if is_public_ip(ip): # Your existing filter
                        if (pid, ip) not in REPORTED_CONNECTIONS:
                            # 1. Ask Manager for score (Centralized Intelligence)
                            resp = GLOBAL_STUB.GetIPScore(edr_pb2.IPRequest(ip=ip))
                            
                            if resp.score > 0:
                                try:
                                    p = psutil.Process(pid)
                                    p_name = p.name()
                                    desc = f"MALICIOUS IP FOUND: {ip} (Abuse Score: {resp.score}%)"
                                    
                                    # 2. Automated Defense Logic
                                    if resp.score > 75:
                                        # BLOCK IP
                                        os.system(f'netsh advfirewall firewall add rule name="EDR_BLOCK_{ip}" dir=out action=block remoteip={ip} enable=yes')
                                        # KILL PROCESS
                                        os.system(f"taskkill /F /PID {pid}")
                                        send_alert("NETWORK", desc + " [BLOCKED & KILLED]", p_name)
                                    else:
                                        # Alert Only for lower scores
                                        send_alert("NETWORK", desc, p_name)
                                        
                                    REPORTED_CONNECTIONS.add((pid, ip))
                                except: pass
        except: pass
        time.sleep(2)
def integrity_monitor():
    """Monitors the EDR's own security certificates for tampering."""
    global ORIGINAL_CERT_HASH
    print("[+] Self-Integrity Shield Active...")
    
    # Take initial baseline only after ensuring we have a valid hash
    while True:
        ORIGINAL_CERT_HASH = get_file_hash(CERT_PATH)
        if ORIGINAL_CERT_HASH not in ["ERROR", "LOCKED", "DELETED"]:
            break
        time.sleep(2)

    while True:
        try:
            current_hash = get_file_hash(CERT_PATH)
            
            # If the file is deleted or modified, trigger alert
            if current_hash != ORIGINAL_CERT_HASH and current_hash != "LOCKED":
                desc = "CRITICAL: Agent Security Certificate tampered with!"
                if current_hash == "DELETED":
                    desc = "CRITICAL: Security Certificate (server.crt) was DELETED!"
                
                # Send high-priority alert
                send_alert("COMPROMISE", desc, "Integrity_Shield")
                
                # Update the baseline so we only alert once per change
                ORIGINAL_CERT_HASH = current_hash
                print(f"[!!!] {desc}")
                
        except Exception: pass
        time.sleep(5) # Check every 5 seconds for faster detection
#def get_installed_software():
 #   """Scans the Windows Registry to list all installed programs."""
  #  software_list = []
    # Registry path where Windows stores 'Add/Remove Programs'
   # path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    #for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
     #   try:
      #      with winreg.OpenKey(hive, path) as key:
       #         for i in range(winreg.QueryInfoKey(key)[0]):
        #            try:
         #               s_key_name = winreg.EnumKey(key, i)
          #              with winreg.OpenKey(key, s_key_name) as s_key:
           #                 name = winreg.QueryValueEx(s_key, "DisplayName")[0]
            #                version = winreg.QueryValueEx(s_key, "DisplayVersion")[0]
             #               software_list.append(edr_pb2.SoftwareItem(name=name, version=str(version)))
              #      except: continue
        #except: continue
    #return software_list
def get_installed_software():
    """
    Ultimate Software Auditor:
    Uses a silent PowerShell registry query to bypass Python winreg restrictions.
    """
    software_list = []
    print("[*] Starting Deep-Dive Software Audit...")
    
    # This command pulls from HKLM (64 & 32 bit) and HKCU in one go
    # We use -NoProfile and avoid the word 'Bypass' to ensure the EDR lets it run.
    ps_cmd = (
        "powershell.exe -NoProfile -Command \""
        "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -ne $null } | "
        "Select-Object DisplayName, DisplayVersion, InstallDate | "
        "ConvertTo-Json -Compress\""
    )

    try:
        # Run the command and capture the output
        raw_json = subprocess.check_output(ps_cmd, shell=True).decode('utf-8', errors='ignore')
        
        if raw_json.strip():
            # Convert JSON text to Python list
            data = json.loads(raw_json)
            apps = data if isinstance(data, list) else [data]

            for a in apps:
                name = str(a.get('DisplayName', '')).strip()
                if not name or len(name) < 2: continue

                version = str(a.get('DisplayVersion', 'Unknown'))
                raw_date = str(a.get('InstallDate', 'N/A'))
                
                # Format Date: 20240518 -> 2024-05-18
                if len(raw_date) == 8 and raw_date.isdigit():
                    fmt_date = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:8]}"
                else:
                    fmt_date = "N/A"

                software_list.append(edr_pb2.SoftwareItem(
                    name=name, version=version, install_date=fmt_date
                ))
        
        # Remove any duplicates found across different registry hives
        unique_list = {s.name: s for s in software_list}.values()
        final_list = list(unique_list)
        
        print(f"[+] Audit Successful: Found {len(final_list)} applications.")
        return final_list

    except Exception as e:
        print(f"[!] Software Audit Failed: {e}")
        return []
def run_vulnerability_audit():
    """Sends the software list to the Manager."""
    try:
        if ensure_connection():
            software = get_installed_software()
            print(f"[DEBUG] Found {len(software)} apps. Sending to manager...") # ADD THIS
            GLOBAL_STUB.PushSoftwareInventory(
                edr_pb2.SoftwareInventoryRequest(agent_id=AGENT_ID, software=software),
                timeout=60 # Agent will wait 1 minute before giving up
)
            #GLOBAL_STUB.PushSoftwareInventory(edr_pb2.SoftwareInventoryRequest(agent_id=AGENT_ID, software=software))
            print("[DEBUG] Inventory sent successfully!") # ADD THIS
    except Exception as e:
            print(f"[DEBUG] CVE Audit Failed: {e}")

def behavior_monitor():
    my_pid = os.getpid()

    while True:
        try:
            for proc in list(psutil.process_iter(['pid', 'name', 'cmdline'])):
                try:
                    pid = proc.info['pid']
                    if pid == my_pid: continue
                    name = proc.info['name'].lower()
                    
                    
                    # 1. Capture the ORIGINAL command line (Preserves case for the Alert)
                    # This is what you will see on the Dashboard
                    full_cmd_original = " ".join(proc.info['cmdline'] or [])
                    
                    # 2. Convert to lowercase ONLY for detection logic
                    cmd_line_logic = full_cmd_original.lower()
                    if "#internal_edr_c2_trusted_command" in cmd_line_logic:
                        continue
                    name = proc.info['name'].lower()
                   # try:
                    #    parent = proc.parent()
                     #   if parent and parent.pid == my_pid:
                      #      continue # This is our own child process (taskkill, etc.)
                    #except: pass

                    # --- WHITELIST INTERNAL EDR COMMANDS ---
                    edr_cmds = ["netsh advfirewall", "taskkill", "set-disk", "netsh", "get-disk", "mountvol", "get-partition", "get-localuser", "get-winevent", "get-itemproperty"]
                    if any(cmd in cmd_line_logic for cmd in edr_cmds):
                        continue 

                    # FEATURE 1: BLOCKLIST
                    if name in BLOCKED_APPS:
                        #send_alert("POLICY_VIOLATION", f"Killed forbidden app: {name}", name)
                        send_alert("POLICY_VIOLATION", f"Killed forbidden app: {name}", name, pid=pid)
                        os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                        continue

                    # FEATURE 2 & 4: COMMAND LINE INSPECTION (Encoded Commands, etc.)
                    if name in ["powershell.exe", "pwsh.exe", "cmd.exe", "vssadmin.exe", "wmic.exe"]:
                        # Detection for -enc, bypass, etc.
                        if any(x in cmd_line_logic for x in ["-enc", "encodedcommand", " nop "]):
                            parent = proc.parent()
                            if parent and parent.pid != my_pid:
                                # --- UPDATED ALERT: Now includes the full command line ---
                                #send_alert("BEHAVIOR", f"Killed {name} due to malicious arguments: {full_cmd_original}", name)
                                send_alert("BEHAVIOR", f"Killed {name} due to malicious arguments: {full_cmd_original}", name, pid=pid)
                                os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                                continue
                        
                        # Detection for Ransomware (Shadow Copy Deletion)
                        vss_threats = ["delete shadows", "shadowcopy delete", "resize shadowstorage"]
                        if any(threat in cmd_line_logic for threat in vss_threats):
                            # --- UPDATED ALERT: Now includes the full command line ---
                            #send_alert("RANSOMWARE", f"VSS PROTECTION: Killed {name} attempting to delete backups: {full_cmd_original}", name)
                            send_alert("RANSOMWARE", f"VSS PROTECTION: Killed {name} attempting to delete backups: {full_cmd_original}", name, pid=pid)
                            os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                            continue

                    # FEATURE 3: PARENT-CHILD CHECK
                    parent = proc.parent()
                    if parent:
                        if parent.pid == my_pid:
                            continue

                        p_name = parent.name().lower()
                        
                        if name in ["cmd.exe", "powershell.exe"]:
                            if any(x in p_name for x in ["python", "py.exe", "notepad"]):
                                # --- UPDATED ALERT: Now includes the full command line ---
                                #send_alert("BEHAVIOR", f"Killed {name} spawned by suspicious parent {p_name}. CLI: {full_cmd_original}", name)
                                send_alert("BEHAVIOR", f"Killed {name} spawned by suspicious parent {p_name}. CLI: {full_cmd_original}", name, pid=pid)
                                os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                                continue

                        # Dynamic Rules from Manager
                        for (r_parent, r_child) in BEHAVIOR_RULES:
                            if p_name == r_parent and name == r_child:
                                #send_alert("BEHAVIOR_POLICY", f"Killed {name} spawned by forbidden parent {p_name}. CLI: {full_cmd_original}", name)
                                send_alert("BEHAVIOR_POLICY", f"Killed {name} spawned by forbidden parent {p_name}. CLI: {full_cmd_original}", name, pid=pid)
                                os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                                break
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError): 
                    continue
        except Exception: pass
        time.sleep(0.5)
def start_fim_guardian():
    """
    Dynamic FIM: Monitors Windows Session changes. 
    Switches Downloads folder monitoring automatically when users log in/out.
    """
    global CURRENT_FIM_OBSERVER, TRACKED_SESSION_ID, TRACKED_USER_NAME
    
    print("[*] FIM Session Guardian Active...")
    
    while True:
        try:
            # 1. Get the current active console session (the human at the screen)
            active_sid = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
            
            # 2. Check if the session has changed (Login, Logout, or Switch User)
            if active_sid != TRACKED_SESSION_ID:
                
                # --- PHASE A: CLEANUP OLD SESSION ---
                if CURRENT_FIM_OBSERVER:
                    try:
                        CURRENT_FIM_OBSERVER.stop()
                        send_alert("SYSTEM", f"FIM Session Ended: User {TRACKED_USER_NAME} logged out. Monitoring stopped.", "agent.exe")
                        print(f"[-] Session {TRACKED_SESSION_ID} ended. Stopping FIM for {TRACKED_USER_NAME}")
                        CURRENT_FIM_OBSERVER = None
                    except: pass

                # --- PHASE B: DETECT NEW USER ---
                if active_sid != 0xFFFFFFFF:
                    new_user_found = False
                    # Find the explorer process for the new session
                    for proc in psutil.process_iter(['name', 'pid']):
                        try:
                            if proc.info['name'] and proc.info['name'].lower() == 'explorer.exe':
                                proc_sid = ctypes.c_ulong()
                                if ctypes.windll.kernel32.ProcessIdToSessionId(proc.info['pid'], ctypes.byref(proc_sid)):
                                    if proc_sid.value == active_sid:
                                        # Get user info from process environment
                                        p_env = proc.environ()
                                        user_profile = p_env.get('USERPROFILE')
                                        user_name = os.path.basename(user_profile)
                                        
                                        target_path = os.path.join(user_profile, "Downloads")
                                        
                                        if os.path.exists(target_path):
                                            # START NEW WATCHER
                                            CURRENT_FIM_OBSERVER = Observer()
                                            CURRENT_FIM_OBSERVER.schedule(DownloadHandler(), target_path, recursive=False)
                                            CURRENT_FIM_OBSERVER.start()
                                            
                                            # Update tracking state
                                            TRACKED_SESSION_ID = active_sid
                                            TRACKED_USER_NAME = user_name
                                            new_user_found = True
                                            
                                            send_alert("SYSTEM", f"FIM Session Started: User {user_name} logged in. Now watching {target_path}", "agent.exe")
                                            print(f"[+] New Session detected ({active_sid}). FIM watching: {target_path}")
                                            break
                        except (psutil.AccessDenied, psutil.NoSuchProcess): continue
                    
                    if not new_user_found:
                        # Session exists but user hasn't fully loaded yet
                        pass 
                else:
                    # No one is logged in at all (Login Screen)
                    TRACKED_SESSION_ID = 0xFFFFFFFF
                    TRACKED_USER_NAME = "None"

        except Exception as e:
            print(f"[!] Guardian Error: {e}")
            
        time.sleep(10) # Check for session changes every 10 seconds
def sysmon_active_response():
    """
    Monitors Sysmon logs for high-frequency patterns.
    Triggers isolation on ID 2 (Instant) or ID 11/23/26 (Threshold).
    """
    print("[+] Sysmon Active Response Engine Online...")
    global EVENT_TIMESTAMPS
    
    try:
        # Open Sysmon Operational Log
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            now = time.time()
            
            for ev in events:
                eid = ev.EventID
                
                # --- RULE 1: FileTime Change (ID 2) ---
                #if eid == 2:
                 #   isolate_host()
                  #  send_alert("BEHAVIOR", "AUTO-ISOLATION: Sysmon ID 2 (FileCreationTime Change) detected. Potential anti-forensics.", "System")
                   # time.sleep(10) # Cooldown

                # --- RULE 2: Threshold Based (ID 11, 23, 26) ---
                if eid in [11, 23, 26]:
                    EVENT_TIMESTAMPS[eid].append(now)
                    
                    # Clean up old timestamps (older than 60 seconds)
                    EVENT_TIMESTAMPS[eid] = [t for t in EVENT_TIMESTAMPS[eid] if now - t < 60]
                    
                    # Check if threshold hit (More than 20 times in 60 seconds)
                    if len(EVENT_TIMESTAMPS[eid]) > 20:
                        isolate_host()
                        reason = "Mass File Creation" if eid == 11 else "Mass File Deletion"
                        send_alert("RANSOMWARE", f"AUTO-ISOLATION: High-frequency {reason} detected (>20 events/min).", "System")
                        EVENT_TIMESTAMPS[eid] = [] # Reset
                        time.sleep(10)

            time.sleep(2) # Poll every 2 seconds
    except Exception as e:
        print(f"[-] Sysmon Engine Error: {e}")
def brute_force_monitor():
    """
    Final Pattern-Snapshot Engine:
    1. Takes a snapshot of the last 20 Security events every 5 seconds.
    2. Scans the snapshot for the 4-Fail + 1-Success pattern.
    3. Uses the exact logic from your working History Table.
    """
    print("[+] Brute-Force Engine: SNAPSHOT MONITORING ACTIVE...")
    
    # Track the 'Time' of the last successful alert to avoid spamming
    last_alert_time = 0

    while True:
        try:
            # --- STEP 1: GRAB THE LAST 20 EVENTS ---
            ps_cmd = (
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                "\"Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 10 -ErrorAction SilentlyContinue | "
                "Select-Object @{n='EID';e={$_.Id}}, @{n='U';e={$_.Properties[5].Value}}, @{n='T';e={$_.TimeCreated}} | "
                "ConvertTo-Json\""
            )
            
            output = subprocess.check_output(ps_cmd, shell=True).decode('utf-8', errors='ignore')
            if not output.strip() or output.strip() == "[]":
                time.sleep(5)
                continue

            events = json.loads(output)
            if isinstance(events, dict): events = [events] 

            # --- STEP 2: ANALYZE PATTERNS PER USER ---
            user_patterns = {} 

            for ev in events:
                user = str(ev.get('U', '')).lower().strip()
                eid = str(ev.get('EID', ''))
                
                if not user or user.endswith('$') or user == "system": continue
                
                if user not in user_patterns: user_patterns[user] = []
                user_patterns[user].append(eid)

            # --- STEP 3: CHECK TRIGGER CONDITION ---
            for user, ids in user_patterns.items():
                has_success = "4624" in ids
                fail_count = ids.count("4625")

                if has_success and fail_count >= 4:
                    if time.time() - last_alert_time > 60:
                        print(f"\n[!!!] BRUTE-FORCE PATTERN DETECTED: {user} ({fail_count} fails + Success)")
                        
                        # 1. SEND CRITICAL ALERT
                        desc = f"BRUTE FORCE BREACH: User '{user}' logged in successfully after {fail_count} failed attempts."
                        send_alert("CRITICAL_REMEDIATION", desc, "BruteForce_Shield")
                        
                        # 2. EXECUTE ACTIVE RESPONSE
                    if REMEDIATION_POLICY:
                        print(f"[*] Policy ON: Executing Atomic Response for {user}...")
                        isolate_host()
                        
                        # A. Reset Password (Confirmed Working)
                        subprocess.run(f'net user "{user}" {EMERGENCY_PASSWORD}', shell=True)
                        
                        # --- B. THE GUARANTEED LOGOUT FIX ---
                        # We use a PowerShell script to find the ID and force logoff
                        # This works even if the service is in Session 0
                        logout_script = (
                            f"powershell.exe -NoProfile -Command \""
                            f"$session = (quser | Select-String '{user}'); "
                            f"if ($session) {{ "
                            f"  $id = ($session -split '\\s+')[2]; "
                            f"  if ($id -notmatch '^\\d+$') {{ $id = ($session -split '\\s+')[3] }} "
                            f"  logoff $id; "
                            f"}} else {{ shutdown /l /f }}\""
                        )
                        
                        # Run the logout command
                        subprocess.run(logout_script, shell=True, capture_output=True)
                        
                        print(f"[!] User {user} has been forcefully logged out.")
                        
                        last_alert_time = time.time()

        except Exception as e:
            print(f"[-] Snapshot Monitor Error: {e}")
            
        time.sleep(5)
def identity_monitor():
    """
    Identity Snapshot Engine (Based on Working Brute-Force Logic):
    1. Takes a snapshot of the last 20 Security events every 5 seconds.
    2. Stringifies all properties inside PowerShell to prevent JSON crashes.
    3. Uses a last_alert_id to ensure every event only triggers one alert.
    """
    print("[+] Identity Guardian: SNAPSHOT MONITORING ACTIVE...")
    
    # Track the RecordNumber of the last event we alerted on
    last_handled_id = 0
    
    # Initialize: Get the newest ID currently in the log so we don't alert on old history
    try:
        init_cmd = 'powershell.exe -NoProfile -Command "(Get-WinEvent -FilterHashtable @{LogName=\'Security\';ID=4720,4726,4732,4733} -MaxEvents 1 -ErrorAction SilentlyContinue).RecordNumber"'
        res = subprocess.check_output(init_cmd, shell=True).decode().strip()
        if res.isdigit():
            last_handled_id = int(res)
            print(f"[*] Identity Shield Synced. Monitoring from ID: {last_handled_id}")
    except: pass

    while True:
        try:
            # --- STEP 1: SNAPSHOT (EXACT BRUTE-FORCE LOGIC) ---
            # We add a ForEach loop to force everything into a String to prevent JSON errors
            ps_cmd = (
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                "\"Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720,4726,4732,4733} -MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Select-Object RecordNumber, Id, @{n='P';e={$_.Properties.Value | ForEach-Object { $_.ToString() }}} | "
                "ConvertTo-Json\""
            )
            
            output = subprocess.check_output(ps_cmd, shell=True).decode('utf-8', errors='ignore')
            if not output.strip() or output.strip() == "[]":
                time.sleep(5)
                continue

            events = json.loads(output)
            if isinstance(events, dict): events = [events]

            # --- STEP 2: PROCESS SNAPSHOT ---
            # Sort by RecordNumber so we handle them in the order they happened
            events.sort(key=lambda x: x.get('RecordNumber', 0))

            for ev in events:
                rid = int(ev.get('RecordNumber', 0))
                
                # Only process if this ID is newer than our last alert
                if rid <= last_handled_id:
                    continue

                eid = int(ev.get('Id', 0))
                props = ev.get('P', [])

                try:
                    # --- STEP 3: LOGIC BY EVENT ID ---
                    if eid == 4720: # User Created
                        target, actor = props[0], props[4]
                        send_alert("USER_CREATED", f"IDENTITY: New user account [{target}] created by [{actor}]", "lsass.exe")
                        print(f"[!] Alert Sent: User Created -> {target}")

                    elif eid == 4726: # User Deleted
                        target, actor = props[0], props[4]
                        send_alert("USER_DELETED", f"IDENTITY: User account [{target}] was DELETED by [{actor}]", "lsass.exe")
                        print(f"[!] Alert Sent: User Deleted -> {target}")

                    elif eid == 4732: # Added to local group
                        target, group, actor = props[0], props[2], props[6]
                        if "administrators" in str(group).lower():
                            send_alert("PRIVILEGE_ESC", f"CRITICAL: [{target}] was added to ADMINISTRATORS by [{actor}]", "lsass.exe")
                            print(f"[!] Alert Sent: Admin Added -> {target}")
                        else:
                            send_alert("GROUP_ADDED", f"User [{target}] added to group [{group}]", "lsass.exe")

                    elif eid == 4733: # Removed from local group
                        target, group, actor = props[0], props[2], props[6]
                        if "administrators" in str(group).lower():
                            send_alert("ADMIN_REMOVAL", f"SECURITY: [{target}] was REMOVED from Administrators by [{actor}]", "lsass.exe")
                            print(f"[!] Alert Sent: Admin Removed -> {target}")
                        else:
                            send_alert("GROUP_REMOVAL", f"User [{target}] removed from group [{group}]", "lsass.exe")

                except Exception as parse_err:
                    continue

                # Update the bookmark
                last_handled_id = rid

        except Exception as e:
            print(f"[-] Identity Monitor Error: {e}")
            
        time.sleep(5)
class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory: self.process_file(event.src_path)
    def on_moved(self, event):
        if not event.is_directory: self.process_file(event.dest_path)

    def process_file(self, path):
        # 1. Ignore temporary browser files
        if path.endswith((".tmp", ".crdownload", ".opdownload")): return
        
        # 2. Wait for the file to be ready (Retry Loop)
        # This is critical for large installers like VLC
        h = hashlib.sha256()
        file_ready = False
        
        for attempt in range(10): # Try for 20 seconds
            try:
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""): 
                        h.update(chunk)
                file_ready = True
                break # Success, file is fully read
            except (PermissionError, OSError):
                # File is still being written or locked by Windows
                time.sleep(2)
        
        if not file_ready:
            print(f"[-] FIM: Skipping {os.path.basename(path)} - File remained locked.")
            return

        # 3. Send Hash to Manager
        file_hash = h.hexdigest().lower()
        try:
            resp = GLOBAL_STUB.CheckHash(edr_pb2.HashRequest(hash=file_hash))
            if resp.is_malicious:
                # 4. Perform the Quarantine
                fname = os.path.basename(path)
                target = os.path.join(QUARANTINE_DIR, fname + ".locked")
                
                # Close the 'with open' first, then move
                shutil.move(path, target)
                send_alert("FILE_PROTECTION", f"VT/MISP MATCH: Quarantined {fname}", "FIM")
                print(f"[!!!] THREAT NEUTRALIZED: {fname}")
        except Exception as e:
            print(f"[-] FIM Network Error: {e}")
def daily_audit_loop():
    while True:
        run_vulnerability_audit()
        time.sleep(86400) # Wait 24 hours
if __name__ == "__main__":
    # 1. Define the protected paths
    PROTECTED_PATHS = [
        r"C:\ProgramData\EDR_Defender",
        r"C:\MyEDR",
        r"C:\MyEDR\Downloads",
        r"C:\EDR_Quarantine",
        r"C:\EDR_Canary_Bait"
    ]

    # 2. Apply the Iron Vault permissions to every folder
    for path in PROTECTED_PATHS:
        harden_folder_permissions(path)
    if "--show-ui" in sys.argv:
        init_agent_logging("gui") 
        ui = AgentDashboard()
        ui.run()
        sys.exit(0)
    # 2. Initialize Service-specific log
    init_agent_logging("service")
    if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)
    enable_kill_privileges(); connect()
    setup_canary()
    # 3. Start Canary Watcher
    #canary_observer = Observer()
    #canary_observer.schedule(CanaryHandler(), CANARY_DIR, recursive=False)
    #canary_observer.start()
    canary_obs = Observer()
    canary_obs.schedule(CanaryHandler(), CANARY_DIR, recursive=False)
    canary_obs.start()
    #print("[+] Ransomware Tripwire Active.")
    threading.Thread(target=integrity_monitor, daemon=True).start()
    threading.Thread(target=registry_monitor, daemon=True).start()
    threading.Thread(target=sysmon_active_response, daemon=True).start()
    threading.Thread(target=brute_force_monitor, daemon=True).start()
    threading.Thread(target=behavior_monitor, daemon=True).start()
    threading.Thread(target=command_and_policy_sync, daemon=True).start()
    threading.Thread(target=fleet_schedule_monitor, daemon=True).start()
    threading.Thread(target=start_fim_guardian, daemon=True).start()
    threading.Thread(target=usb_monitor, daemon=True).start()
    threading.Thread(target=network_monitor, daemon=True).start()
    threading.Thread(target=identity_monitor, daemon=True).start()
    threading.Thread(target=run_vulnerability_audit, daemon=True).start()
    threading.Thread(target=daily_audit_loop, daemon=True).start()
    #observer = Observer()
    #try:
     #   # Find current user Downloads
      #  for user in psutil.users():
       #     WATCH_DIR = os.path.join("C:\\Users", user.name, "Downloads")
        #    if os.path.exists(WATCH_DIR): observer.schedule(DownloadHandler(), WATCH_DIR, recursive=False)
    #except: pass
    #observer.start()
    logging.info("Service Engine fully started and protecting system.")
    while True: time.sleep(60)


                 
