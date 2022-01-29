from cryptography.fernet import Fernet, InvalidToken
from json.decoder import JSONDecodeError
from json import load
import argparse


def read_json_file(path) -> dict:
    """
    Читает JSON файл, возвращает словарь.
    :param path: str
    :return: dict
    """
    with open(path, 'r') as file:
        return load(file)


def get_decrypted_value(token, encrypted_value) -> bytes:
    """
    Расшифровывает строки по алгоритму Фернет.
    :param token: str
    :param encrypted_value: str
    :return: bytes
    """
    fernet = Fernet(token)
    value = fernet.decrypt(encrypted_value.encode())
    return value


def init_args_parser() -> argparse.ArgumentParser:
    """
    Инициализация парсера аргументов.
    :return:
    """
    parser = argparse.ArgumentParser(description='Fernet decoder.')
    parser.add_argument('-f', '--file', type=str, help='Input JSON file', default="./files/message.json")
    return parser


def main():
    parser = init_args_parser()
    file_path = parser.parse_args().file

    try:
        json = read_json_file(file_path)
    except FileNotFoundError as e:
        print(f" Файл '{file_path}' не найден!")
        return
    except JSONDecodeError as e:
        print("Ошибка при расшифровке файла JSON!")
        return

    for token, string in json.items():
        try:
            decrypted_value = get_decrypted_value(token, string)
        except (InvalidToken, ValueError):
            print("Ошибка! Не удалось расшифровать запись!")
        else:
            print(decrypted_value.decode())


if __name__ == '__main__':
    main()
