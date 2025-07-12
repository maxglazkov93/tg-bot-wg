#!/bin/bash

# Скрипт для получения информации о WireGuard сервере
# Запускать с правами root

set -e

echo "🔧 Получение информации о WireGuard сервере..."

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Этот скрипт должен быть запущен с правами root"
    exit 1
fi

# Проверка установки WireGuard
if ! command -v wg &> /dev/null; then
    echo "❌ WireGuard не установлен!"
    exit 1
fi

# Проверка статуса WireGuard
echo "📋 Проверка статуса WireGuard..."
if systemctl is-active --quiet wg-quick@wg0; then
    echo "✅ WireGuard запущен"
else
    echo "⚠️  WireGuard не запущен"
fi

# Получение ключей сервера
if [ -f "/etc/wireguard/private.key" ] && [ -f "/etc/wireguard/public.key" ]; then
    PRIVATE_KEY=$(cat /etc/wireguard/private.key)
    PUBLIC_KEY=$(cat /etc/wireguard/public.key)
    
    echo "📋 Публичный ключ сервера: $PUBLIC_KEY"
    echo "🔒 Приватный ключ сервера: $PRIVATE_KEY"
else
    echo "⚠️  Ключи сервера не найдены"
fi

# Проверка конфигурации
if [ -f "/etc/wireguard/wg0.conf" ]; then
    echo "✅ Конфигурация сервера найдена"
    
    # Получение текущих клиентов
    echo "📋 Текущие клиенты:"
    wg show | grep -A 10 "peer:" || echo "   Нет подключенных клиентов"
else
    echo "⚠️  Конфигурация сервера не найдена"
fi

# Проверка директории клиентов
if [ -d "/etc/wireguard/clients" ]; then
    echo "✅ Директория клиентов найдена"
    CLIENT_COUNT=$(ls /etc/wireguard/clients/*.conf 2>/dev/null | wc -l)
    echo "📁 Количество конфигураций клиентов: $CLIENT_COUNT"
else
    echo "⚠️  Директория клиентов не найдена"
fi

echo ""
echo "📋 Информация для настройки бота:"
echo "   IP сервера: 5.129.213.216"
echo "   Порт: 65338"
echo "   Подсеть: 10.66.66.0/24"
echo "   IPv6-подсеть: fd42:42:42:1/64"
echo "   DNS: 1.1.1.1, 1.0.0.1"
echo ""
echo "🔧 Для управления WireGuard используйте:"
echo "   sudo wg show                    # Показать статус"
echo "   sudo systemctl status wg-quick@wg0  # Статус сервиса"
echo "   sudo systemctl restart wg-quick@wg0 # Перезапуск"
echo "   ls /etc/wireguard/clients/      # Список конфигураций клиентов" 