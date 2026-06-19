import socket
import ssl

from config import COMMON_PORTS, SERVICES


def check_port(ip, port):
    """Перевіряє, чи відкритий TCP-порт на вказаній IP-адресі."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    finally:
        sock.close()


def detect_service(port):
    """Повертає назву служби за номером порту."""
    return SERVICES.get(port, "Невідома служба")


def detect_hostname(ip):
    """Повертає ім'я вузла за IP-адресою, якщо воно доступне."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Невідоме ім'я"


def receive_text(sock, max_bytes=1024):
    """Отримує текстову відповідь від служби."""
    try:
        data = sock.recv(max_bytes)
        if not data:
            return ""
        return data.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, OSError):
        return ""


def parse_http_banner(response_text):
    """Повертає найінформативніший рядок HTTP-відповіді."""
    if not response_text:
        return "HTTP-відповідь не отримано"

    lines = [line.strip() for line in response_text.splitlines() if line.strip()]

    if not lines:
        return "HTTP-відповідь отримано, але банер відсутній"

    for line in lines:
        if line.lower().startswith("server:"):
            return line

    return lines[0]


def get_http_banner(ip):
    """Отримує банер HTTP-служби."""
    try:
        with socket.create_connection((ip, 80), timeout=1.5) as sock:
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
            response_text = receive_text(sock)
            return parse_http_banner(response_text)
    except OSError:
        return "HTTP-банер не отримано"


def get_https_banner(ip):
    """Отримує банер HTTPS-служби через TLS-з'єднання."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, 443), timeout=2) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                tls_sock.settimeout(1.5)
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                tls_sock.sendall(request.encode("ascii", errors="ignore"))
                response_text = receive_text(tls_sock)
                return parse_http_banner(response_text)
    except OSError:
        return "HTTPS-банер не отримано"


def get_text_protocol_banner(ip, port):
    """Отримує банер служб, які повертають текст одразу після підключення."""
    try:
        with socket.create_connection((ip, port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            banner = receive_text(sock)
            if banner:
                return banner
            return "Банер не отримано"
    except OSError:
        return "Банер не отримано"


def get_port_banner(ip, port):
    """Повертає банер для конкретного порту."""
    if port == 80:
        return get_http_banner(ip)

    if port == 443:
        return get_https_banner(ip)

    if port in {21, 22, 25, 110, 143}:
        return get_text_protocol_banner(ip, port)

    return "Банер не реалізовано для цієї служби"


def scan_host_ports(ip):
    """Сканує порти вузла та повертає ім'я вузла і деталі відкритих портів."""
    hostname = detect_hostname(ip)
    port_results = []

    for port in COMMON_PORTS:
        if check_port(ip, port):
            service = detect_service(port)
            banner = get_port_banner(ip, port)

            port_results.append({
                "порт": port,
                "служба": service,
                "банер": banner
            })

    return hostname, port_results