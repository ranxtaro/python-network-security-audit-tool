import ipaddress
import platform
import re
import socket
import subprocess

from config import DEFAULT_MANUAL_NETWORK, MAC_VENDOR_PREFIXES


def get_local_ip():
    """Повертає локальну IP-адресу поточного комп'ютера."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    finally:
        sock.close()

    return local_ip


def get_target_network(manual_network=None):
    """Повертає мережу для сканування."""
    manual_value = manual_network or DEFAULT_MANUAL_NETWORK

    if manual_value:
        return ipaddress.ip_network(manual_value, strict=False)

    local_ip = get_local_ip()

    if not ipaddress.ip_address(local_ip).is_private:
        return None

    return ipaddress.ip_network(f"{local_ip}/24", strict=False)


def is_host_active(ip):
    """Перевіряє, чи відповідає вузол на ping."""
    system_name = platform.system().lower()

    if "windows" in system_name:
        command = ["ping", "-n", "1", "-w", "400", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]

    result = run_hidden_command(command)

    return result.returncode == 0


def normalize_mac(mac):
    """Нормалізує MAC-адресу до формату AA:BB:CC:DD:EE:FF."""
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")

    if len(parts) != 6:
        return "Невідомо"

    normalized_parts = []
    for part in parts:
        if len(part) == 1:
            part = "0" + part
        normalized_parts.append(part)

    return ":".join(normalized_parts)


def get_mac_address(ip):
    """Повертає MAC-адресу вузла через ARP-таблицю, якщо вона доступна."""
    system_name = platform.system().lower()

    try:
        if "windows" in system_name:
            command = ["arp", "-a", ip]
        else:
            command = ["arp", "-n", ip]

        run_kwargs = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "ignore"
        }

        if "windows" in system_name:
            run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(command, **run_kwargs)
        output = result.stdout

        mac_match = re.search(
            r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",
            output
        )

        if mac_match:
            return normalize_mac(mac_match.group(0))

    except OSError:
        pass

    return "Невідомо"


def detect_vendor_by_mac(mac_address):
    """Повертає виробника за MAC-адресою."""
    if mac_address == "Невідомо":
        return None

    prefix = ":".join(mac_address.split(":")[:3])

    return MAC_VENDOR_PREFIXES.get(prefix)


def detect_vendor_by_hostname(hostname):
    """Повертає імовірного виробника за ім'ям вузла."""
    if not hostname or hostname == "Невідоме ім'я":
        return None

    hostname_lower = hostname.lower()

    # Якщо це просто клієнт у домені fritz.box, не вважаємо його автоматично AVM
    # Наприклад: mykyta.fritz.box або mykytas-ipad.fritz.box
    if hostname_lower.endswith(".fritz.box"):
        base_name = hostname_lower.replace(".fritz.box", "")
        if base_name not in {"fritz", "fritzbox", "router", "repeater", "mesh"}:
            # Не визначаємо AVM тільки через домен fritz.box
            hostname_lower = base_name

    rules = [
        (["ipad", "iphone", "macbook", "imac", "apple-tv", "apple tv", "airpods", "ios"], "Apple"),
        (["fritz", "fritzbox"], "AVM"),
        (["tp-link", "tplink"], "TP-Link"),
        (["mikrotik"], "MikroTik"),
        (["synology"], "Synology"),
        (["samsung"], "Samsung"),
        (["dlink", "d-link"], "D-Link"),
        (["asus", "asustek"], "Asustek"),
        (["raspberrypi", "raspberry-pi", "raspberry"], "Raspberry Pi"),
        (["vmware"], "VMware"),
        (["virtualbox"], "Oracle VirtualBox"),
        (["hyper-v"], "Microsoft Hyper-V"),
        (["huawei"], "Huawei"),
        (["xiaomi"], "Xiaomi"),
        (["honor"], "Honor"),
        (["oppo"], "Oppo"),
        (["vivo"], "Vivo"),
        (["realme"], "Realme"),
        (["oneplus"], "OnePlus"),
        (["lenovo"], "Lenovo"),
        (["hp", "hewlett"], "HP"),
        (["dell"], "Dell"),
        (["acer"], "Acer"),
        (["msi"], "MSI"),
        (["intel"], "Intel"),
        (["canon"], "Canon"),
        (["epson"], "Epson"),
        (["brother"], "Brother")
    ]

    for keywords, vendor in rules:
        for keyword in keywords:
            if keyword in hostname_lower:
                return vendor

    return None


def detect_vendor(mac_address, hostname):
    """
    Повертає виробника пристрою.
    Спочатку за MAC-адресою, якщо не вдалося — за ім'ям вузла.
    """
    vendor_by_mac = detect_vendor_by_mac(mac_address)
    if vendor_by_mac:
        return vendor_by_mac

    vendor_by_hostname = detect_vendor_by_hostname(hostname)
    if vendor_by_hostname:
        return f"{vendor_by_hostname} (за ім'ям вузла)"

    return "Невідомий виробник"

def run_hidden_command(command):
    """Запускає системну команду без показу консольного вікна у Windows."""
    system_name = platform.system().lower()

    run_kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL
    }

    if "windows" in system_name:
        run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    return subprocess.run(command, **run_kwargs)

def detect_device_type(hostname, vendor, open_ports, services):
    """Повертає імовірний тип пристрою."""
    hostname_lower = hostname.lower() if hostname else ""
    vendor_lower = vendor.lower() if vendor else ""
    service_set = set(services)

    # Якщо це клієнт у домені fritz.box, виділяємо базове ім'я
    base_hostname = hostname_lower
    if hostname_lower.endswith(".fritz.box"):
        stripped = hostname_lower.replace(".fritz.box", "")
        if stripped:
            base_hostname = stripped

    # Мобільні пристрої
    mobile_keywords = ["iphone", "ipad", "android", "phone", "smartphone", "tablet"]
    if any(keyword in base_hostname for keyword in mobile_keywords):
        return "Смартфон або планшет"

    # Принтери
    printer_keywords = ["printer", "epson", "canon", "brother", "hp-print", "xerox"]
    if any(keyword in base_hostname for keyword in printer_keywords):
        return "Принтер"

    if any(name in vendor_lower for name in ["canon", "epson", "brother"]):
        return "Принтер"

    # NAS
    if "synology" in base_hostname or "nas" in base_hostname:
        return "Мережеве сховище"

    # Віртуальні машини
    if any(name in vendor_lower for name in ["vmware", "virtualbox", "hyper-v"]):
        return "Віртуальна машина"

    # Якщо відкритий SMB, це скоріше ПК або файловий вузол, а не роутер
    if 445 in open_ports and "SMB" in service_set:
        return "Комп'ютер або файловий вузол"

    # Типовий ПК / ноутбук
    computer_keywords = ["desktop", "laptop", "pc", "notebook", "macbook", "imac", "mykyta"]
    if any(keyword in base_hostname for keyword in computer_keywords):
        return "Комп'ютер або ноутбук"

    if 3389 in open_ports:
        return "Комп'ютер або ноутбук"

    # Маршрутизатори / репітери / мережеві пристрої
    infrastructure_keywords = ["fritz", "fritzbox", "router", "gateway", "repeater", "mesh"]
    if any(keyword in base_hostname for keyword in infrastructure_keywords):
        if 80 in open_ports or 443 in open_ports:
            return "Маршрутизатор"
        return "Мережевий пристрій"

    if any(name in vendor_lower for name in ["avm", "mikrotik", "tp-link", "d-link", "asustek"]):
        if 80 in open_ports or 443 in open_ports:
            return "Мережевий пристрій"
        return "Мережевий пристрій"

    # Якщо є лише веб-інтерфейс, це часто інфраструктурний пристрій
    if 80 in open_ports and 443 in open_ports and 445 not in open_ports and 3389 not in open_ports:
        return "Мережевий пристрій"

    # Apple без точнішого визначення
    if "apple" in vendor_lower:
        return "Пристрій Apple"

    return "Невідомий тип"