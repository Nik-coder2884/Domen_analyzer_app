import sys
import re
from typing import Optional

# Импортируем функции из ранее созданных модулей
from api_client import fetch_whois_data
from data_processor import process_whois_data
from report import generate_report


def get_domain_from_user() -> Optional[str]:
    """
    Запрашивает доменное имя у пользователя через терминал.
    Корректно обрабатывает кириллицу, преобразуя её в Punycode (IDNA)
    с помощью встроенных средств Python.
    """
    try:
        domain = input("Введите доменное имя (например, yandex.ru или яндекс.рф): ").strip().lower()

        if not domain:
            print("\nДоменное имя не введено. Выход из программы.")
            return None

        # Проверка на наличие кириллицы или других не-ASCII символов
        try:
            domain.encode('ascii')
            is_international = False
        except UnicodeEncodeError:
            is_international = True

        if is_international:
            try:
                # Преобразуем кириллический домен в Punycode встроенными средствами
                # encode('idna') возвращает байты, декодируем их обратно в строку
                domain = domain.encode('idna').decode('ascii')
                print(f"\nДомен преобразован в Punycode для запроса: {domain}")
            except Exception:
                print("\nОшибка: введенное доменное имя содержит недопустимые символы.")
                return get_domain_from_user()

        # --- Далее идут стандартные проверки для уже ASCII-совместимого домена ---

        if len(domain) > 253:
            print("\nОшибка: доменное имя слишком длинное (максимум 253 символа).")
            return get_domain_from_user()

        if not re.match(r'^[a-z0-9.-]+$', domain):
            print("\nОшибка: домен содержит недопустимые символы после преобразования.")
            return get_domain_from_user()

        if "." not in domain:
            print("\nОшибка: доменное имя должно содержать точку.")
            return get_domain_from_user()

        if domain.startswith(('-', '.')) or domain.endswith(('-', '.')):
            print("\nОшибка: домен не может начинаться или заканчиваться на дефис или точку.")
            return get_domain_from_user()

        if '..' in domain:
            print("\nОшибка: домен содержит пустую метку (две точки подряд).")
            return get_domain_from_user()

        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                print(f"\nОшибка: часть домена '{label}' слишком длинная (максимум 63 символа).")
                return get_domain_from_user()
            if label.startswith('-') or label.endswith('-'):
                print(f"\nОшибка: метка '{label}' не может начинаться или заканчиваться на дефис.")
                return get_domain_from_user()

        return domain

    except (KeyboardInterrupt, EOFError):
        print("\n\nПолучен сигнал прерывания. Выход из программы.")
        return None


def main():
    print("=" * 50)
    print(" " * 10 + "WHOIS-КОНСОЛЬНЫЙ СБОРЩИК ДАННЫХ")
    print("=" * 50)

    domain = get_domain_from_user()

    if domain is None:
        sys.exit(0)

    print(f"\nИдет запрос данных для: {domain}...")

    raw_data = fetch_whois_data(domain)

    if raw_data is None:
        print("\nОшибка: не удалось получить данные от WHOIS-сервера.")
        print("Проверьте интернет-соединение и корректность доменного имени.")
        sys.exit(1)

    processed_data = process_whois_data(raw_data)

    generate_report(processed_data)


if __name__ == "__main__":
    main()