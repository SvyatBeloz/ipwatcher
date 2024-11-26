#!/bin/bash

# Отправка уведомления о конфликте
if command -v notify-send &> /dev/null; then
    notify-send "IP конфликт!" "Обнаружен конфликт IP-адресов:\nИнтерфейс: $1\nIP: $2\nMAC: $3"
fi
