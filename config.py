#!/usr/bin/env python3
import logging
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Optional

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
