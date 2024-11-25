#!/usr/bin/env python3
import logging
import sys
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

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
                raw_data = f.read()

            # Определяем формат файла и загружаем
            if str(self.config_path).endswith(('.yaml', '.yml')) or not raw_data.startswith('{'):
                logging.debug("Parsing as YAML format")
                self.cfg = yaml.safe_load(raw_data)
            else:
                logging.debug("Parsing as JSON format")
                self.cfg = json.loads(raw_data)

            # Загрузка настроек мониторинга
            self.monitoring = self._parse_monitoring(self.cfg.get('monitoring', 'all'))
            
            # Active mode
            active_cfg = self.cfg.get('active_mode', {})
            if isinstance(active_cfg, bool):
                self.active_enabled = active_cfg
                self.active_interval = 10
            else:
                self.active_enabled = active_cfg.get('enabled', True)
                self.active_interval = active_cfg.get('interval', 10)

            # Passive mode
            passive_cfg = self.cfg.get('passive_mode', {})
            if isinstance(passive_cfg, bool):
                self.passive_enabled = passive_cfg
            else:
                self.passive_enabled = passive_cfg.get('enabled', True)

            # Conflict actions
            self.conflict_actions = self.cfg.get('conflict_actions', [])

            # Logging
            log_cfg = self.cfg.get('logging', {})
            if isinstance(log_cfg, str):
                self.log_level = log_cfg.upper()
            else:
                self.log_level = log_cfg.get('level', 'INFO').upper()
            
            logging.info(f"Загружена конфигурация: {self.monitoring}")

        except Exception as e:
            logging.error(f"Ошибка при загрузке конфигурации: {e}")
            sys.exit(1)

    def _parse_monitoring(self, monitoring_cfg: Union[str, List, Dict]) -> Dict[str, Any]:
        """
        Парсит конфигурацию мониторинга и возвращает словарь:
        {
            'interface_name': 'all' | {'include': [...], 'exclude': [...]}
        }
        """
        result = {}
        
        # Вариант 1: monitoring: all
        if monitoring_cfg == 'all':
            import netifaces
            for iface in netifaces.interfaces():
                if not iface.startswith('lo'):  # Пропускаем локальный интерфейс
                    result[iface] = 'all'
            return result

        # Вариант 2: список интерфейсов
        if isinstance(monitoring_cfg, list):
            for item in monitoring_cfg:
                if isinstance(item, str):
                    result[item] = 'all'
                elif isinstance(item, dict):
                    for iface, settings in item.items():
                        if settings == 'all':
                            result[iface] = 'all'
                        elif isinstance(settings, (list, dict)):
                            if isinstance(settings, list):
                                result[iface] = {'include': settings, 'exclude': []}
                            else:
                                result[iface] = {
                                    'include': settings.get('include', 'all'),
                                    'exclude': settings.get('exclude', [])
                                }

        # Вариант 3: словарь с настройками
        elif isinstance(monitoring_cfg, dict):
            for iface, settings in monitoring_cfg.items():
                if settings == 'all':
                    result[iface] = 'all'
                elif isinstance(settings, (list, dict)):
                    if isinstance(settings, list):
                        result[iface] = {'include': settings, 'exclude': []}
                    else:
                        result[iface] = {
                            'include': settings.get('include', 'all'),
                            'exclude': settings.get('exclude', [])
                        }

        return result

    def should_monitor_ip(self, interface: str, ip: str) -> bool:
        """
        Проверяет, нужно ли отслеживать данный IP на данном интерфейсе
        """
        if interface not in self.monitoring:
            return False
        
        settings = self.monitoring[interface]
        
        # Если для интерфейса указано 'all'
        if settings == 'all':
            return True
            
        # Если есть детальные настройки
        if isinstance(settings, dict):
            # Проверяем исключения
            if ip in settings.get('exclude', []):
                return False
                
            include = settings.get('include', 'all')
            # Если include == 'all' или IP в списке include
            return include == 'all' or ip in include
            
        return False
