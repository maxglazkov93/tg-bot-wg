import os

# Загрузка параметров из файла
def load_config_from_file():
    config = {}
    try:
        with open('api_token.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
    except FileNotFoundError:
        raise FileNotFoundError("Файл api_token.txt не найден!")
    return config

# Загружаем конфигурацию
config_data = load_config_from_file()

# Telegram Bot настройки
BOT_TOKEN = config_data.get('token', '').replace('token = ', '')

# PIN код для доступа (6 цифр)
ACCESS_PIN = config_data.get('ACCESS_PIN', '123456')  # Измените на свой PIN

# WireGuard сервер настройки
WG_SERVER_IP = config_data.get('WG_SERVER_IP', '5.129.213.216')  # Внешний IP сервера
WG_SERVER_PORT = int(config_data.get('WG_SERVER_PORT', '65338'))  # Порт WireGuard
WG_SERVER_PUBLIC_KEY = config_data.get('SERVER_PUB_KEY', '')  # Публичный ключ сервера
WG_SERVER_PRIVATE_KEY = config_data.get('SERVER_PRIV_KEY', '')  # Приватный ключ сервера

# SSH настройки для подключения к серверу
SSH_HOST = config_data.get('SSH_HOST', '5.129.213.216')
SSH_PORT = int(config_data.get('SSH_PORT', '22'))
SSH_USERNAME = config_data.get('SSH_USERNAME', 'root')  # или ваш пользователь
SSH_PASSWORD = config_data.get('SSH_PASSWORD', 'your_password')  # или путь к SSH ключу
SSH_KEY_PATH = config_data.get('SSH_KEY_PATH', None)  # Путь к SSH ключу, если используете

# WireGuard настройки
WG_INTERFACE = config_data.get('WG_INTERFACE', 'wg0')
WG_CONFIG_PATH = config_data.get('WG_CONFIG_PATH', '/etc/wireguard/wg0.conf')
WG_CLIENTS_DIR = config_data.get('WG_CLIENTS_DIR', '/etc/wireguard/clients')

# Настройки клиентов
CLIENT_DNS = config_data.get('CLIENT_DNS', '1.1.1.1, 1.0.0.1')
CLIENT_ALLOWED_IPS = config_data.get('CLIENT_ALLOWED_IPS', '0.0.0.0/0,::/0') 