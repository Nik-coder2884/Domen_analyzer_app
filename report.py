from typing import Dict


def generate_report(data: Dict[str, str]) -> None:
    """
    Принимает словарь с девятью полями от data_processor.py
    и выводит их в терминал в виде читаемого списка.
    Если значение поля равно 'нет данных', выводит его в скобках.
    """

    # Словарь для красивых заголовков (учтен порядок полей из ТЗ)
    labels = {
        'domain_name': 'Доменное имя',
        'owner': 'Владелец или организация',
        'registrar': 'Регистратор',
        'creation_date': 'Дата регистрации',
        'expiration_date': 'Дата истечения',
        'updated_date': 'Дата последнего обновления',
        'name_servers': 'Серверы имён',
        'status': 'Статус домена',
        'country': 'Страна регистранта'
    }

    print("\n" + "=" * 50)
    print(" " * 15 + "ОТЧЕТ ПО ДОМЕНУ")
    print("=" * 50)

    # Определяем максимальную длину заголовка для красивого выравнивания
    max_label_len = max(len(label) for label in labels.values()) + 2

    for key in [
        'domain_name', 'owner', 'registrar', 'creation_date',
        'expiration_date', 'updated_date', 'name_servers', 'status', 'country'
    ]:
        value = data.get(key, "нет данных")

        # Если данных нет, визуально выделяем это
        display_value = f"({value})" if value == "нет данных" else value

        # Выводим строку с выравниванием по двоеточию
        print(f"{labels[key] + ':':<{max_label_len}} {display_value}")

    print("=" * 50 + "\n")