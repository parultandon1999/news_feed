import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================
# Configure your MySQL database connection here
MYSQL_CONFIG = {
    'host': '127.0.0.1',           # MySQL server host
    'port': 3306,                   # MySQL server port
    'database': 'thecyberfeed',     # Database name
    'user': 'cyberfeed_user',       # Database user
    'password': '12345',            # Database password
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'autocommit': False
}

# ============================================================================
# SERVER CONFIGURATION
# ============================================================================
HOST = "0.0.0.0"                    # Server host (0.0.0.0 = all interfaces)
PORT = 5000                         # Server port
DEBUG = True                        # Debug mode (set to False for production)

# ============================================================================
# SECURITY SETTINGS
# ============================================================================
# Flask secret key for session encryption
FLASK_SECRET_KEY = "e4ee2847abd5cdb87398c320568c1923873c2e83e87a1a1a9af41378ccb9566b"

# Settings page password
SETTINGS_PASSWORD = "admin123"

# ============================================================================
# EXTERNAL API CONFIGURATION
# ============================================================================
# CVE / NVD API
CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "072c14e3-fd92-40a7-9b67-a3b262dc5046"  # NVD API Key

# Exploit-DB
EXPLOIT_DB_API = "https://www.exploit-db.com/search"

# MalwareBazaar
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
MALWARE_BAZAAR_API_KEY = ""  # Optional: Get from https://bazaar.abuse.ch/api/

# Ransomware Intelligence
RANSOMWARE_TRACKER = "https://ransomwaretracker.abuse.ch/downloads"
RANSOMWARE_LIVE_API = "https://api.ransomware.live/v2"
RANSOMWARE_LIVE_API_KEY = ""  # Optional: Get from https://ransomware.live/
RANSOMLOOK_API = "https://www.ransomlook.io/api"  # RansomLook.io API

# CERT-In
CERT_IN_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02"

# ============================================================================
# SCHEDULER SETTINGS
# ============================================================================
FETCH_INTERVAL_MINUTES = 30         # Auto-fetch interval (minutes)
CVE_FETCH_INTERVAL_HOURS = 2        # CVE fetch interval (hours)

# ============================================================================
# APPLICATION SETTINGS
# ============================================================================
ITEMS_PER_PAGE = 50                 # Pagination

# Branding
COMPANY_NAME = "eSec Forte"
PROJECT_NAME = "Security Intelligence"

# Validation
if not SETTINGS_PASSWORD and not DEBUG:
    raise ValueError("SETTINGS_PASSWORD must be set in config.py for production deployment")

if not FLASK_SECRET_KEY and not DEBUG:
    raise ValueError("FLASK_SECRET_KEY must be set in config.py for production deployment")
