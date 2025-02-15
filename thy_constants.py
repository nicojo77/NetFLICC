"""
Contains constants.
Needs adapting to suit NetFLICC and Zeek installation paths.
"""

installation_path = "/home/anon/Documents/git/pythonScripts/netflicc/"

# Location of Zeek plugins and packages: importXP.py.
ZEEK_PLUGIN = f"{installation_path}CONSTANTS/geoip.zeek"
ZEEK_PACKAGES = "/opt/zeek/share/zeek/site/packages/"

# APIs keys and already checked cell-towers: celloc.py.
OPENCELLID = f"{installation_path}/CONSTANTS/cell_towers.parquet"
GOOGLE_API_KEY = "AIzaSyAopPBHDH2C5LUSE4FRKoKI91YAEu6sdzc"
COMBAIN_API_KEY = "vspbj06gzxdzpkjd7714"
API_CACHED_ONEYEAR = f"{installation_path}CONSTANTS/API_CACHED_ONEYEAR.parquet"
API_CACHED_ONEDAY = f"{installation_path}CONSTANTS/API_CACHED_ONEDAY.parquet"

# Location of Tor exit nodes: newapps.py.
DAN_TXT= f"{installation_path}CONSTANTS/dan.txt"
PATH_APP_ICONS = f"{installation_path}app_icons/"

# Location of Telegram IP Addresses list: telegram.py.
TELEGRAM_IPS = f"{installation_path}CONSTANTS/ips.txt"

# Location of html templates: reportGen.py.
TEMPLATES = f"{installation_path}templates/"

# Location of tacdb.txt: gsma.py.
GSMA = f"{installation_path}TACDB/tacdb.txt"

# Location for testing pcaps.
TEST_PATH = f"{installation_path}test_pcaps/"
