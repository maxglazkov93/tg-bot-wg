import os
import subprocess
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
import paramiko
from config import *

class WireGuardManager:
    def __init__(self):
        self.ssh_client = None
        
    def generate_key_pair(self):
        """Генерирует пару ключей для клиента"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Конвертируем в base64 для WireGuard (44 символа)
        import base64
        private_key_b64 = base64.b64encode(private_key_bytes).decode('utf-8')
        public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
        
        return private_key_b64, public_key_b64
    
    def create_client_config(self, client_name, client_private_key, client_public_key, client_ip, client_ipv6=None):
        """Создает конфигурацию клиента WireGuard"""
        address_line = f"Address = {client_ip}/32"
        if client_ipv6:
            address_line += f",{client_ipv6}/64"
        config = f"""[Interface]
PrivateKey = {client_private_key}
{address_line}
DNS = {CLIENT_DNS}

[Peer]
PublicKey = {WG_SERVER_PUBLIC_KEY}
Endpoint = {WG_SERVER_IP}:{WG_SERVER_PORT}
AllowedIPs = {CLIENT_ALLOWED_IPS}
"""
        return config
    
    def connect_ssh(self):
        """Подключается к серверу по SSH"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if SSH_KEY_PATH:
                self.ssh_client.connect(
                    SSH_HOST, 
                    port=SSH_PORT, 
                    username=SSH_USERNAME,
                    key_filename=SSH_KEY_PATH
                )
            else:
                self.ssh_client.connect(
                    SSH_HOST, 
                    port=SSH_PORT, 
                    username=SSH_USERNAME,
                    password=SSH_PASSWORD
                )
            return True
        except Exception as e:
            print(f"Ошибка подключения SSH: {e}")
            return False
    
    def disconnect_ssh(self):
        """Отключается от SSH"""
        if self.ssh_client:
            self.ssh_client.close()
    
    def check_client_name_exists(self, client_name):
        """Проверяет, существует ли уже конфигурация с таким именем"""
        if not self.connect_ssh():
            return False
        try:
            sftp = self.ssh_client.open_sftp()
            try:
                sftp.stat(f"{WG_CLIENTS_DIR}/{client_name}.conf")
                return True  # Файл существует
            except FileNotFoundError:
                return False  # Файл не найден
            finally:
                sftp.close()
        except Exception as e:
            print(f"Ошибка проверки имени клиента: {e}")
            return False
        finally:
            self.disconnect_ssh()
    
    def get_next_client_ip(self):
        """Получает следующий доступный IP для клиента и соответствующий IPv6"""
        if not self.connect_ssh():
            return None, None
        try:
            # Получаем список существующих файлов клиентов
            stdin, stdout, stderr = self.ssh_client.exec_command(f"ls {WG_CLIENTS_DIR}/*.conf 2>/dev/null || echo ''")
            client_files = stdout.read().decode().strip().split('\n')
            
            used_octets = []
            used_ipv6 = []
            
            # Читаем каждый файл клиента и извлекаем IP-адреса
            for client_file in client_files:
                if client_file.strip():
                    try:
                        stdin, stdout, stderr = self.ssh_client.exec_command(f"cat {client_file}")
                        client_config = stdout.read().decode()
                        
                        for line in client_config.split('\n'):
                            if line.startswith('Address = '):
                                ips = line.split('=')[1].strip().split(',')
                                for ip in ips:
                                    ip = ip.strip().split('/')[0]
                                    if ip.startswith('10.66.66.'):
                                        try:
                                            octet = int(ip.split('.')[-1])
                                            used_octets.append(octet)
                                        except Exception:
                                            pass
                                    elif ip.startswith('fd42:42:42:1::'):
                                        try:
                                            n = int(ip.split('::')[-1])
                                            used_ipv6.append(n)
                                        except Exception:
                                            pass
                    except Exception as e:
                        print(f"Ошибка чтения файла {client_file}: {e}")
                        continue
            
            # Если нет ни одного, начинаем с 2
            if not used_octets:
                next_octet = 2
            else:
                next_octet = max(used_octets) + 1
            
            if next_octet > 254:
                return None, None  # Нет свободных адресов
            
            next_ipv4 = f"10.66.66.{next_octet}"
            next_ipv6 = f"fd42:42:42:1::{next_octet}"
            
            print(f"Debug: used_octets={used_octets}, next_octet={next_octet}")
            return next_ipv4, next_ipv6
            
        except Exception as e:
            print(f"Ошибка получения IP: {e}")
        finally:
            self.disconnect_ssh()
        return None, None
    
    def add_client_to_server(self, client_name, client_public_key, client_ip, client_private_key):
        """Добавляет клиента в конфигурацию сервера"""
        if not self.connect_ssh():
            return False
            
        try:
            # Создаем конфигурацию клиента в директории clients
            client_config = self.create_client_config(
                client_name, 
                client_private_key, 
                client_public_key, 
                client_ip
            )
            
            # Сохраняем конфигурацию клиента в файл
            client_config_path = f"{WG_CLIENTS_DIR}/{client_name}.conf"
            stdin, stdout, stderr = self.ssh_client.exec_command(f"echo '{client_config}' > {client_config_path}")
            
            # Добавляем нового клиента в конфигурацию сервера
            peer_config = f"""

# Client: {client_name}
[Peer]
PublicKey = {client_public_key}
AllowedIPs = {client_ip}/32
"""
            
            # Добавляем в конец файла конфигурации сервера
            stdin, stdout, stderr = self.ssh_client.exec_command(f"echo '{peer_config}' >> {WG_CONFIG_PATH}")
            
            # Перезапускаем WireGuard
            stdin, stdout, stderr = self.ssh_client.exec_command(f"wg syncconf {WG_INTERFACE} <(wg-quick strip {WG_INTERFACE})")
            
            return True
            
        except Exception as e:
            print(f"Ошибка добавления клиента: {e}")
            return False
        finally:
            self.disconnect_ssh()
    
    def create_and_deploy_config(self, client_name):
        """Создает конфигурацию клиента и разворачивает на сервере"""
        try:
            # Генерируем ключи
            private_key, public_key = self.generate_key_pair()
            # Получаем IP для клиента
            client_ip, client_ipv6 = self.get_next_client_ip()
            if not client_ip:
                return None, "Не удалось получить IP адрес"
            # Создаем конфигурацию клиента
            client_config = self.create_client_config(
                client_name, private_key, public_key, client_ip, client_ipv6
            )
            # Добавляем клиента на сервер
            if not self.add_client_to_server(client_name, public_key, client_ip, private_key):
                return None, "Не удалось добавить клиента на сервер"
            return client_config, None
        except Exception as e:
            return None, f"Ошибка создания конфигурации: {e}" 

class WireGuardManagerLocal:
    def __init__(self):
        pass

    def generate_key_pair(self):
        return WireGuardManager().generate_key_pair()

    def create_client_config(self, client_name, client_private_key, client_public_key, client_ip, client_ipv6=None):
        return WireGuardManager().create_client_config(client_name, client_private_key, client_public_key, client_ip, client_ipv6)

    def check_client_name_exists(self, client_name):
        path = os.path.join(WG_CLIENTS_DIR, f"{client_name}.conf")
        return os.path.isfile(path)

    def get_next_client_ip(self):
        used_octets = []
        used_ipv6 = []
        if not os.path.isdir(WG_CLIENTS_DIR):
            os.makedirs(WG_CLIENTS_DIR)
        for fname in os.listdir(WG_CLIENTS_DIR):
            if fname.endswith('.conf'):
                with open(os.path.join(WG_CLIENTS_DIR, fname), 'r') as f:
                    for line in f:
                        if line.startswith('Address = '):
                            ips = line.split('=')[1].strip().split(',')
                            for ip in ips:
                                ip = ip.strip().split('/')[0]
                                if ip.startswith('10.66.66.'):
                                    try:
                                        octet = int(ip.split('.')[-1])
                                        used_octets.append(octet)
                                    except Exception:
                                        pass
                                elif ip.startswith('fd42:42:42:1::'):
                                    try:
                                        n = int(ip.split('::')[-1])
                                        used_ipv6.append(n)
                                    except Exception:
                                        pass
        next_octet = max(used_octets) + 1 if used_octets else 2
        if next_octet > 254:
            return None, None
        next_ipv4 = f"10.66.66.{next_octet}"
        next_ipv6 = f"fd42:42:42:1::{next_octet}"
        return next_ipv4, next_ipv6

    def add_client_to_server(self, client_name, client_public_key, client_ip, client_private_key):
        # Создаем конфиг клиента
        client_config = self.create_client_config(client_name, client_private_key, client_public_key, client_ip)
        client_config_path = os.path.join(WG_CLIENTS_DIR, f"{client_name}.conf")
        with open(client_config_path, 'w') as f:
            f.write(client_config)
        # Добавляем peer в серверный конфиг
        peer_config = f"\n\n# Client: {client_name}\n[Peer]\nPublicKey = {client_public_key}\nAllowedIPs = {client_ip}/32\n"
        with open(WG_CONFIG_PATH, 'a') as f:
            f.write(peer_config)
        # Перезапуск wg
        try:
            subprocess.run(["wg-quick", "down", WG_INTERFACE], check=True)
        except Exception:
            pass  # если не поднят, игнорируем
        subprocess.run(["wg-quick", "up", WG_INTERFACE], check=True)
        return True

    def create_and_deploy_config(self, client_name):
        try:
            private_key, public_key = self.generate_key_pair()
            client_ip, client_ipv6 = self.get_next_client_ip()
            if not client_ip:
                return None, "Не удалось получить IP адрес"
            client_config = self.create_client_config(client_name, private_key, public_key, client_ip, client_ipv6)
            if not self.add_client_to_server(client_name, public_key, client_ip, private_key):
                return None, "Не удалось добавить клиента на сервер"
            return client_config, None
        except Exception as e:
            return None, f"Ошибка создания конфигурации: {e}" 