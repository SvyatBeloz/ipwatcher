#!/bin/bash

# Создаем директорию для конфигурации
sudo mkdir -p /etc/ipwatcher

# Копируем конфигурационный файл
sudo cp config.yaml /etc/ipwatcher/
# sudo cp config.json /etc/ipwatcher/

# Устанавливаем правильные права доступа
sudo chmod 644 /etc/ipwatcher/config.yaml
# sudo chmod 644 /etc/ipwatcher/config.json