#!/bin/bash

# Создаем директорию для логов, если она не существует
mkdir -p "$HOME/.local/share/ipwatcher"

# Логирование конфликта IP-адресов
echo "[$(date '+%Y-%m-%d %H:%M:%S')] IP конфликт: Интерфейс=$1, IP=$2, MAC=$3" >> "$HOME/.local/share/ipwatcher/conflicts.log"
