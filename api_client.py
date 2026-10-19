import whois
import requests
import re
import socket
from typing import Any, Dict, Optional
import sys

# Определяем исключение для разных версий библиотеки
try:
    from whois.parser import WhoisException
except ImportError:
    try:
        from whois import WhoisException
    except ImportError:
        # Если исключения нет, создадим базовое
        class WhoisException(Exception):
            pass


def fetch_whois_data(domain: str) -> Optional[Dict[str, Any]]:
    """
    Универсальный сборщик WHOIS.
    Для .рф использует HTTP-запрос, для остальных — библиотеку.
    """

    # Проверка доступа в интернет
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
    except OSError:
        print("\nОшибка: нет доступа к интернету.", file=sys.stderr)
        return None

    # Если домен в зоне .рф, сразу идем по пути HTTP (библиотека его не тянет)
    if domain.endswith('.рф') or domain.endswith('.xn--p1ai'):
        return _fetch_via_http(domain)

    # Для всех остальных зон пробуем библиотеку
    try:
        print("Выполняется запрос через библиотеку python-whois...", file=sys.stderr)
        raw_data = whois.whois(domain)

        if raw_data and hasattr(raw_data, 'domain_name') and raw_data.domain_name:
            return raw_data

    except (WhoisException, Exception) as e:
        print(f"Запрос через библиотеку не удался: {e}", file=sys.stderr)
        # Если библиотека не справилась, пробуем HTTP как резерв
        return _fetch_via_http(domain)

    return None


def _fetch_via_http(domain: str) -> Optional[Dict[str, Any]]:
    """
    Резервный метод получения данных через веб-страницу whois.com.
    """
    try:
        print("Выполняется резервный запрос через HTTP (whois.com)...", file=sys.stderr)
        url = f"https://www.whois.com/whois/{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        text = response.text

        # Создаем объект-макет, чтобы data_processor.py не выдал ошибку
        class MockWhois:
            pass

        mock = MockWhois()
        mock.domain_name = domain

        # Регистратор
        reg_match = re.search(r'Registrar:\s*(.+?)(?:\n|<)', text, re.IGNORECASE)
        mock.registrar = reg_match.group(1).strip() if reg_match else "нет данных"

        # Дата создания
        date_match = re.search(r'Creation Date:\s*(.+)', text, re.IGNORECASE)
        mock.creation_date = date_match.group(1).strip() if date_match else "нет данных"

        # Дата истечения
        exp_match = re.search(r'Registry Expiry Date:\s*(.+)', text, re.IGNORECASE)
        mock.expiration_date = exp_match.group(1).strip() if exp_match else "нет данных"

        # Дата обновления (Updated Date)
        upd_match = re.search(r'Updated Date:\s*(.+)', text, re.IGNORECASE)
        mock.updated_date = upd_match.group(1).strip() if upd_match else "нет данных"

        # Серверы имен
        ns_matches = re.findall(r'Name Server:\s*(.+)', text, re.IGNORECASE)
        mock.name_servers = [ns.strip().lower() for ns in ns_matches] if ns_matches else "нет данных"

        # Статус
        status_matches = re.findall(r'Status:\s*(.+)', text, re.IGNORECASE)
        mock.status = [s.strip() for s in status_matches] if status_matches else "нет данных"

        # Владелец/Организация (часто скрыта, но попробуем найти)
        org_match = re.search(r'Registrant Organization:\s*(.+)', text, re.IGNORECASE)
        if not org_match:
            org_match = re.search(r'Organization:\s*(.+)', text, re.IGNORECASE)
        mock.org = org_match.group(1).strip() if org_match else "нет данных"

        # Страна
        country_match = re.search(r'Registrant Country:\s*(.+)', text, re.IGNORECASE)
        mock.registrant_country = country_match.group(1).strip() if country_match else "нет данных"

        return mock

    except Exception as e:
        print(f"Резервный HTTP-запрос также завершился ошибкой: {e}", file=sys.stderr)
        return None