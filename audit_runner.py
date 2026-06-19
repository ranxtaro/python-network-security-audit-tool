from network_scanner import (
    detect_device_type,
    detect_vendor,
    get_mac_address,
    get_target_network,
    is_host_active
)
from port_scanner import scan_host_ports
from risk_analyzer import analyze_risks, summarize_risks
from report_generator import build_report, save_reports


def run_audit(
    manual_network=None,
    log_callback=None,
    progress_callback=None,
    stop_callback=None
):
    """Запускає повний аудит мережі та повертає дані звіту."""

    def log(message=""):
        if log_callback:
            log_callback(message)

    def progress(value, text=""):
        if progress_callback:
            progress_callback(value, text)

    def should_stop():
        if stop_callback:
            return stop_callback()
        return False

    network = get_target_network(manual_network)

    if network is None:
        log("Не вдалося автоматично визначити приватну локальну мережу.")
        log("Укажіть мережу вручну, наприклад: 192.168.178.0/24")
        progress(0, "Помилка визначення мережі")
        return None

    hosts_to_check = list(network.hosts())
    total_hosts = len(hosts_to_check)

    log(f"Локальна мережа для перевірки: {network}")
    log("Сканування може тривати 1-2 хвилини.")
    log("")

    progress(0, "Підготовка до сканування")

    active_hosts = []

    for index, host in enumerate(hosts_to_check, start=1):
        if should_stop():
            log("")
            log("Сканування зупинено користувачем під час пошуку активних вузлів.")
            break

        ip = str(host)

        if is_host_active(ip):
            log(f"[АКТИВНИЙ] {ip}")
            active_hosts.append(ip)

        if total_hosts > 0:
            percent = int((index / total_hosts) * 50)
            progress(percent, f"Пошук активних вузлів: {index}/{total_hosts}")

    log("")
    log("Починаємо сканування портів активних вузлів...")
    log("")

    host_results = []
    active_total = len(active_hosts)

    for index, ip in enumerate(active_hosts, start=1):
        if should_stop():
            log("")
            log("Сканування зупинено користувачем під час перевірки активних вузлів.")
            break

        hostname, port_results = scan_host_ports(ip)
        mac_address = get_mac_address(ip)
        vendor = detect_vendor(mac_address, hostname)

        open_ports = [item["порт"] for item in port_results]
        services = [item["служба"] for item in port_results]
        risks = analyze_risks(open_ports)
        device_type = detect_device_type(hostname, vendor, open_ports, services)

        host_result = {
            "ip": ip,
            "hostname": hostname,
            "mac_address": mac_address,
            "vendor": vendor,
            "device_type": device_type,
            "портові_дані": port_results,
            "відкриті_порти": open_ports,
            "служби": services,
            "ризики": risks
        }
        host_results.append(host_result)

        log(f"Вузол: {ip}")
        log(f"  Ім'я вузла: {hostname}")
        log(f"  MAC-адреса: {mac_address}")
        log(f"  Виробник: {vendor}")
        log(f"  Тип пристрою: {device_type}")

        if port_results:
            for item in port_results:
                log(f"  [ВІДКРИТО] Порт {item['порт']} ({item['служба']})")
                log(f"    Банер: {item['банер']}")
        else:
            log("  Відкритих портів із перевірюваного списку не виявлено")

        if risks:
            log("  Ризики:")
            for risk in risks:
                port_text = "Н/Д" if risk["порт"] is None else str(risk["порт"])
                log(f"    - {risk['рівень']} | Порт {port_text} | {risk['опис']}")
        else:
            log("  Ризики не виявлено")

        log("")

        if active_total > 0:
            percent = 50 + int((index / active_total) * 45)
            progress(percent, f"Сканування активних вузлів: {index}/{active_total}")

    risk_summary = summarize_risks(host_results)

    log("ПІДСУМОК ЗА РИЗИКАМИ")
    log(f"  Високий рівень: {risk_summary['high']}")
    log(f"  Середній рівень: {risk_summary['medium']}")
    log(f"  Низький рівень: {risk_summary['low']}")
    log(f"  Усього ризиків: {risk_summary['total']}")
    log(f"  Вузлів із ризиками: {risk_summary['hosts_with_risks']}")
    log("")

    progress(97, "Формування звітів")
    report_data = build_report(network, host_results, risk_summary)
    save_reports(report_data)

    if should_stop():
        progress(100, "Сканування зупинено")
        log("Формування часткового звіту завершено.")
        log("Створено файли звіту: zvit_audytu.json, zvit_audytu.txt та zvit_audytu.html")
        return report_data

    progress(100, "Сканування завершено")
    log("Сканування завершено.")
    log("Створено файли звіту: zvit_audytu.json, zvit_audytu.txt та zvit_audytu.html")

    return report_data