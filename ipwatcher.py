#!/usr/bin/env python3
import asyncio
import logging
import subprocess
import sys
import yaml
import time
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Dict, List, Optional
from functools import partial
import threading

from colorama import Fore, Style, init as colorama_init
from scapy.all import ARP, Ether, srp, sniff, conf

# Initialize colorama
colorama_init()

# Define log colors
LOG_COLORS = {
    'DEBUG': Fore.CYAN,
    'INFO': Fore.GREEN,
    'WARNING': Fore.YELLOW,
    'ERROR': Fore.RED,
    'CRITICAL': Fore.MAGENTA + Style.BRIGHT
}

# Configuration defaults
DEFAULT_CONFIG_PATH = Path("/etc/ipwatcher/config.yaml")


class Config:
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.load_config()

    def load_config(self):
        if not self.config_path.exists():
            logging.error(f"Configuration file not found at {self.config_path}")
            sys.exit(1)
        try:
            with open(self.config_path, 'r') as f:
                self.cfg = yaml.safe_load(f)

            # Загрузка настроек мониторинга
            self.monitoring = self._parse_monitoring(self.cfg.get('monitoring', 'all'))
            
            # Active mode
            active_cfg = self.cfg.get('active_mode', {})
            self.active_enabled = active_cfg.get('enabled', True)
            self.active_interval = active_cfg.get('interval', 10)

            # Passive mode
            passive_cfg = self.cfg.get('passive_mode', {})
            self.passive_enabled = passive_cfg.get('enabled', True)

            # Conflict actions
            self.conflict_actions = self.cfg.get('conflict_actions', [])

            # Logging
            log_cfg = self.cfg.get('logging', {})
            self.log_level = log_cfg.get('level', 'INFO')
            
            logging.info(f"Загружена конфигурация: {self.monitoring}")

        except Exception as e:
            logging.error(f"Ошибка при загрузке конфигурации: {e}")
            sys.exit(1)

    def _parse_monitoring(self, monitoring_cfg) -> Dict[str, List[str]]:
        """
        Парсит конфигурацию мониторинга и возвращает словарь:
        {
            'interface_name': ['ip1', 'ip2'] или ['all'],
            ...
        }
        """
        result = {}
        
        # Вариант 1: monitoring: all
        if monitoring_cfg == 'all':
            # Получаем список всех интерфейсов
            import netifaces
            for iface in netifaces.interfaces():
                if not iface.startswith('lo'):  # Пропускаем локальный интерфейс
                    result[iface] = ['all']
            return result

        # Вариант 2 и 3: список интерфейсов с настройками
        if isinstance(monitoring_cfg, list):
            for item in monitoring_cfg:
                if isinstance(item, dict):
                    for iface, ips in item.items():
                        if ips == 'all':
                            result[iface] = ['all']
                        elif isinstance(ips, list):
                            result[iface] = ips
                        else:
                            logging.warning(f"Неверный формат IP для интерфейса {iface}: {ips}")
                            continue

        return result

    def should_monitor_ip(self, interface: str, ip: str) -> bool:
        """
        Проверяет, нужно ли отслеживать данный IP на данном интерфейсе
        """
        if interface not in self.monitoring:
            return False
        
        ip_list = self.monitoring[interface]
        return 'all' in ip_list or ip in ip_list


class Logger:
    def __init__(self, level: str):
        self.logger = logging.getLogger("IPConflictDetector")
        level = level.upper()  # Преобразуем в верхний регистр
        if not hasattr(logging, level):
            print(f"Неверный уровень логирования: {level}, используется INFO")
            level = "INFO"
        
        self.logger.setLevel(getattr(logging, level))
        self.logger.propagate = False  # Prevent duplicate logs

        # Formatter string с миллисекундами
        formatter_str = '[%(asctime)s.%(msecs)03d] %(levelname)s - %(message)s'
        date_format = '%Y-%m-%dT%H:%M:%S'

        # Console Handler with color
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level))
        console_formatter = self.ColorFormatter(formatter_str, datefmt=date_format)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # SysLog Handler for journalctl
        try:
            syslog_handler = SysLogHandler(address='/dev/log')
            syslog_handler.setLevel(getattr(logging, level))
            syslog_formatter = logging.Formatter(formatter_str, datefmt=date_format)
            syslog_handler.setFormatter(syslog_formatter)
            self.logger.addHandler(syslog_handler)
        except Exception as e:
            print(f"Не удалось настроить syslog: {e}")

        self.logger.debug("Логгер инициализирован")

    class ColorFormatter(logging.Formatter):
        def __init__(self, fmt: str, datefmt: Optional[str] = None):
            super().__init__(fmt, datefmt)

        def format(self, record):
            log_color = LOG_COLORS.get(record.levelname, "")
            reset = Style.RESET_ALL
            if record.msg:
                record.msg = f"{log_color}{record.msg}{reset}"
            return super().format(record)

    def get_logger(self):
        return self.logger


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


class PassiveMonitor:
    def __init__(self, config: Config, logger: logging.Logger, detector: ConflictDetector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()
        # Suppress scapy's verbose output
        conf.verb = 0

    def get_interfaces(self):
        interfaces = []
        for iface, ips in self.config.monitoring.items():
            if 'all' in ips:
                interfaces.append(iface)
        return interfaces

    def start(self):
        for iface in self.interfaces:
            self.logger.info(f"Начало пассивного мониторинга интерфейса {iface}")
            # Используем partial для передачи имени интерфейса в callback
            callback = partial(self.process_packet, iface=iface)
            # Запускаем снифер в отдельном потоке для каждого интерфейса
            threading.Thread(
                target=lambda: sniff(
                    iface=iface,
                    filter="arp",
                    prn=callback,
                    store=0
                ),
                daemon=True
            ).start()

    def process_packet(self, pkt, iface):
        if ARP in pkt:
            # Обрабатываем как ARP-запросы, так и ответы
            if pkt[ARP].op in (1, 2):  # 1 = who-has (request), 2 = is-at (response)
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                self.detector.update_mapping(iface, ip, mac)


class ActiveMonitor:
    def __init__(self, config: Config, logger: logging.Logger, detector: ConflictDetector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()

    def get_interfaces(self):
        interfaces = []
        for iface, ips in self.config.monitoring.items():
            if 'all' in ips:
                interfaces.append(iface)
        return interfaces

    def start(self):
        while True:
            for iface in self.interfaces:
                try:
                    self.logger.debug(f"Отправка ARP-запроса для проверки IP на интерфейсе {iface}")
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="0.0.0.0"),
                        timeout=2,
                        verbose=0,
                        iface=iface
                    )
                    for _, rcv in ans:
                        mac = rcv[ARP].hwsrc
                        ip = rcv[ARP].psrc
                        self.detector.update_mapping(iface, ip, mac)
                except Exception as e:
                    self.logger.error(f"Ошибка при отправке ARP-запроса на интерфейсе {iface}: {e}")
            
            time.sleep(self.config.active_interval)


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
