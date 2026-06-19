from config import RISK_RULES
from port_scanner import detect_service


def analyze_risks(open_ports):
    """Аналізує ризики на основі відкритих портів."""
    risks = []

    for port in open_ports:
        if port in RISK_RULES:
            level, description = RISK_RULES[port]
            risks.append({
                "порт": port,
                "служба": detect_service(port),
                "рівень": level,
                "опис": description
            })

    if 80 in open_ports and 443 not in open_ports:
        risks.append({
            "порт": 80,
            "служба": "HTTP",
            "рівень": "Низький",
            "опис": "Виявлено HTTP без HTTPS"
        })

    if len(open_ports) > 5:
        risks.append({
            "порт": None,
            "служба": "Кілька служб",
            "рівень": "Низький",
            "опис": "На вузлі відкрито багато портів із перевірюваного списку"
        })

    return risks


def summarize_risks(host_results):
    """Формує загальний підсумок за ризиками для всіх вузлів."""
    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "hosts_with_risks": 0
    }

    level_map = {
        "Високий": "high",
        "Середній": "medium",
        "Низький": "low"
    }

    for host in host_results:
        host_has_risks = False

        for risk in host["ризики"]:
            host_has_risks = True
            summary["total"] += 1

            level_key = level_map.get(risk["рівень"])
            if level_key:
                summary[level_key] += 1

        if host_has_risks:
            summary["hosts_with_risks"] += 1

    return summary