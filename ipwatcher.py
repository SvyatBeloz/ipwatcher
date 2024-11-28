#!/usr/bin/env python3
import logging
import subprocess
import sys
import asyncio
from collections import defaultdict
from typing import Dict, List, Optional

from scapy.all import conf

from config import Config
from logger import Logger
from active_monitor import ActiveMonitor
from passive_monitor import PassiveMonitor
from monitoring import NetworkMonitor

class ConflictDetector:
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        # Словарь для хранения MAC-адресов для каждого IP на каждом интерфейсе
        # {interface: {ip: set(mac_addresses)}}
        self.ip_mac_map: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self.conflicts_detected: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

    def update_mapping(self, interface: str, ip: str, mac: str):
        # Проверяем, нужно ли отслеживать этот IP на этом интерфейсе
        if not self.config.should_monitor_ip(interface, ip):
            return

        previous_macs = self.ip_mac_map[interface][ip].copy()
        self.ip_mac_map[interface][ip].add(mac)
        
        if len(self.ip_mac_map[interface][ip]) > 1:
            new_conflicts = self.ip_mac_map[interface][ip] - previous_macs
            for conflicting_mac in new_conflicts:
                if conflicting_mac not in self.conflicts_detected[interface][ip]:
                    self.handle_conflict(interface, ip, conflicting_mac)
                    self.conflicts_detected[interface][ip].add(conflicting_mac)

    def handle_conflict(self, interface: str, ip: str, mac: str):
        self.logger.warning(
            f"Обнаружен конфликт IP-адресов на интерфейсе {interface}! "
            f"IP {ip} используется MAC-адресом {mac}"
        )
        
        for action in self.config.conflict_actions:
            cmd = action.format(**{
                'interface': interface,
                'conflict-ip': ip,
                'adopted-mac': mac
            })
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Ошибка выполнения команды: {e}")

    def handle_ip_conflict(self, interface: str, ip: str, mac: str):
        """Обработка обнаруженного конфликта IP адресов"""
        self.logger.warning(f"Конфликт IP адресов на {interface}:")
        self.logger.warning(f"IP адрес {ip} используется устройством с MAC {mac}")
        
        # TODO: Добавить дополнительные действия при обнаружении конфликта
        # Например:
        # - Отправка уведомления администратору
        # - Запись в базу данных
        # - Автоматическое изменение IP адреса


class IPConflictDetector:
    def __init__(self):
        # Load configuration
        self.config = Config()
        # Set up logging
        self.logger = Logger(self.config.log_level).get_logger()
        # Initialize conflict detector
        self.detector = ConflictDetector(self.config, self.logger)
        # Initialize monitors
        self.passive_monitor = PassiveMonitor(self.config, self.logger, self.detector)
        self.active_monitor = ActiveMonitor(self.config, self.logger, self.detector)

    def run(self):
        async def main():
            tasks = []
            
            # Запускаем базовый мониторинг интерфейсов
            async with self.active_monitor as monitor:
                tasks.append(asyncio.create_task(monitor.monitor_interfaces_changes()))
                
                # Запускаем активный мониторинг если он включен
                if self.config.active_enabled:
                    self.logger.info("Запуск активного мониторинга...")
                    tasks.append(asyncio.create_task(monitor.start_active_monitor()))
                
                # Запускаем пассивный мониторинг если он включен
                if self.config.passive_enabled:
                    self.logger.info("Запуск пассивного мониторинга...")
                    tasks.append(asyncio.create_task(monitor.start_passive_monitor()))

                if not tasks:
                    self.logger.warning("Ни один режим мониторинга не включен в конфигурации!")
                    return

                try:
                    # Запускаем все задачи параллельно
                    await asyncio.gather(*tasks)
                except asyncio.CancelledError:
                    self.logger.info("Получен сигнал остановки, завершаем работу...")
                except Exception as e:
                    self.logger.error(f"Ошибка в процессе мониторинга: {str(e)}")
                finally:
                    # Отменяем все запущенные задачи
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
        
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            self.logger.info("Программа остановлена пользователем")
            sys.exit(0)


if __name__ == "__main__":
    detector = IPConflictDetector()
    detector.run()
