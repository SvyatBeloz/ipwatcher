#!/usr/bin/env python3
import logging
import subprocess
import sys
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional

from scapy.all import conf

from config import Config
from logger import Logger
from active_monitor import ActiveMonitor
from passive_monitor import PassiveMonitor

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
        # Start passive monitoring
        self.passive_monitor.start()
        
        # Start active monitoring in a separate thread if enabled
        if self.config.active_enabled:
            self.logger.info("Запуск активного мониторинга")
            threading.Thread(
                target=self.active_monitor.start,
                daemon=True
            ).start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Программа остановлена пользователем")
            sys.exit(0)


if __name__ == "__main__":
    detector = IPConflictDetector()
    detector.run()
