#!/bin/bash

# Отключение интерфейса при конфликте
if [ "$EUID" -ne 0 ]; then
    echo "Требуются права root для отключения интерфейса"
    exit 1
fi

interface=$1
ip=$2
mac=$3

# Отключаем интерфейс
ip link set $interface down

# Логируем действие
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Отключен интерфейс $interface из-за конфликта IP=$ip MAC=$mac" >> /var/log/ipwatcher_conflicts.log
