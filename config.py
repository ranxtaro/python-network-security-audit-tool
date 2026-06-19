from pathlib import Path
import sys


if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
    RESOURCE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent
    RESOURCE_DIR = BASE_DIR

DEFAULT_MANUAL_NETWORK = None

COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389]

SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

RISK_RULES = {
    21: ("Середній", "FTP - незахищений протокол передавання даних"),
    23: ("Високий", "Telnet - незахищений протокол віддаленого доступу"),
    445: ("Середній", "SMB - спільний доступ до файлів може бути вразливим"),
    3389: ("Середній", "RDP - відкрито віддалений доступ до пристрою")
}

REPORT_JSON_FILE = BASE_DIR / "zvit_audytu.json"
REPORT_TXT_FILE = BASE_DIR / "zvit_audytu.txt"
REPORT_HTML_FILE = BASE_DIR / "zvit_audytu.html"
REPORT_XLSX_FILE = BASE_DIR / "zvit_audytu.xlsx"

TEMPLATE_FILE = RESOURCE_DIR / "templates" / "report_template.html"
STYLE_FILE = RESOURCE_DIR / "static" / "style.css"

MAC_VENDOR_PREFIXES = {
    "00:1A:2B": "Cisco",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:7E": "Apple",
    "00:1F:3F": "Apple",
    "28:CF:E9": "Apple",
    "3C:22:FB": "Apple",
    "40:B0:34": "Apple",
    "58:55:CA": "Apple",
    "60:F8:1D": "Apple",
    "68:5B:35": "Apple",
    "74:E1:B6": "Apple",
    "7C:C3:A1": "Apple",
    "8C:85:90": "Apple",
    "A4:5E:60": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "3C:37:86": "MikroTik",
    "48:8F:5A": "MikroTik",
    "4C:5E:0C": "MikroTik",
    "D4:CA:6D": "MikroTik",
    "00:11:32": "Synology",
    "00:11:22": "Asustek",
    "08:60:6E": "Asustek",
    "10:BF:48": "Asustek",
    "2C:56:DC": "Asustek",
    "30:85:A9": "Asustek",
    "38:2C:4A": "Asustek",
    "50:46:5D": "Asustek",
    "00:1D:0F": "TP-Link",
    "14:CC:20": "TP-Link",
    "18:D6:C7": "TP-Link",
    "50:C7:BF": "TP-Link",
    "84:16:F9": "TP-Link",
    "90:F6:52": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "C0:25:E9": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "00:1E:A6": "Samsung",
    "08:08:C2": "Samsung",
    "28:39:5E": "Samsung",
    "34:23:87": "Samsung",
    "5C:0A:5B": "Samsung",
    "64:B3:10": "Samsung",
    "78:1F:DB": "Samsung",
    "88:32:9B": "Samsung",
    "A8:06:00": "Samsung",
    "BC:14:85": "Samsung",
    "CC:07:AB": "Samsung",
    "E8:50:8B": "Samsung",
    "00:17:9A": "D-Link",
    "1C:7E:E5": "D-Link",
    "34:08:04": "D-Link",
    "5C:D9:98": "D-Link",
    "90:94:E4": "D-Link",
    "C8:BE:19": "D-Link",
    "00:24:D2": "AVM",
    "38:10:D5": "AVM",
    "44:4E:6D": "AVM",
    "4C:ED:FB": "AVM",
    "AC:9A:96": "AVM"
}