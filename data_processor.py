from datetime import datetime
from typing import Any, Dict, List, Optional, Union


def _safe_getattr(obj: Any, attr_names: List[str], default: str = "нет данных") -> Any:
    """
    Безопасное получение атрибута из объекта.
    Проверяет список возможных имен атрибутов (для разных зон, например .ru и .com).
    """
    if obj is None:
        return default

    for name in attr_names:
        value = getattr(obj, name, None)
        if value not in (None, "", [], {}):
            return value
    return default


def _normalize_date(date_obj: Any) -> str:
    """
    Приводит дату к строковому формату ГГГГ-ММ-ДД.
    Если дата приходит списком (бывает в python-whois), берет первый элемент.
    """
    if date_obj is None or date_obj == "нет данных":
        return "нет данных"

    if isinstance(date_obj, list):
        if not date_obj:
            return "нет данных"
        date_obj = date_obj[0]

    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d")

    # Если пришла строка, пытаемся ее распарсить на случай разных форматов
    if isinstance(date_obj, str):
        for fmt in ("%Y-%m-%d", "%Y.%m.%d", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S"):
            try:
                return datetime.strptime(date_obj, fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
        return date_obj  # возвращаем как есть, если формат нераспознан

    return str(date_obj)


def _normalize_list(data: Any) -> str:
    """
    Приводит списки (DNS-серверы, статусы) к строке через запятую.
    """
    if data is None or data == "нет данных":
        return "нет данных"
    if isinstance(data, list):
        return ", ".join([str(item).strip() for item in data if item])
    return str(data).strip()


def process_whois_data(raw_data: Any) -> Dict[str, str]:
    """
    Принимает сырые данные от api_client.fetch_whois_data и извлекает 9 целевых полей.
    Возвращает словарь с нормализованными значениями.
    Если поле отсутствует, возвращает 'нет данных'.
    """

    # 1. Доменное имя (ищем в нескольких возможных ключах)
    domain = _safe_getattr(raw_data, ['domain_name', 'name'])
    if isinstance(domain, list):
        domain = domain[0] if domain else "нет данных"

    # 2. Владелец или организация
    owner = _safe_getattr(raw_data, ['registrant_name', 'org', 'registrant_organization', 'name'])

    # 3. Регистратор
    registrar = _safe_getattr(raw_data, ['registrar', 'registrar_name'])

    # 4. Дата регистрации
    creation_date = _normalize_date(_safe_getattr(raw_data, ['creation_date', 'created_date']))

    # 5. Дата истечения
    expiration_date = _normalize_date(_safe_getattr(raw_data, ['expiration_date', 'expires_date']))

    # 6. Дата последнего обновления
    updated_date = _normalize_date(_safe_getattr(raw_data, ['updated_date', 'changed_date']))

    # 7. Серверы имён
    name_servers = _normalize_list(_safe_getattr(raw_data, ['name_servers', 'nameservers']))

    # 8. Статус домена
    status = _normalize_list(_safe_getattr(raw_data, ['status', 'domain_status']))

    # 9. Страна регистранта
    country = _safe_getattr(raw_data, ['registrant_country', 'country'])

    return {
        'domain_name': str(domain) if domain != "нет данных" else "нет данных",
        'owner': str(owner) if owner != "нет данных" else "нет данных",
        'registrar': str(registrar) if registrar != "нет данных" else "нет данных",
        'creation_date': creation_date,
        'expiration_date': expiration_date,
        'updated_date': updated_date,
        'name_servers': name_servers,
        'status': status,
        'country': str(country) if country != "нет данных" else "нет данных"
    }