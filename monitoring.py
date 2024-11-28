import gc
import array
import fcntl
import logging
import re
import time
from typing import Any, List, Tuple, Optional, Dict
import asyncio
from pyroute2 import IPRoute, NDB
import socket
import struct
import os
import subprocess
import ipaddress

class NetworkMonitor:
    def __init__(self, config, logger: logging.Logger, detector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self._running = True
        self._known_interfaces = {}  # Хранение интерфейсов и их состояний
        self._cache = {}  # Кэш информации об интерфейсах
        self._cache_ttl = 30  # TTL кэша в секундах
        self._check_interval = getattr(config, 'interface_check_interval', 5)
        self._interface_filters = getattr(config, 'interface_filters', [])
        # Словари для хранения IP-адресов каждого интерфейса
        self.interface_ipv4 = {}  # формат: {interface_name: set(ipv4_addresses)}
        self.interface_ipv6 = {}  # формат: {interface_name: set(ipv6_addresses)}
        # Загружаем настройки мониторинга из конфига
        self.monitoring_config = getattr(config, 'cfg', {}).get('monitoring', 'all')

    async def __aenter__(self):
        """Асинхронный контекстный менеджер для корректной инициализации"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Корректное завершение работы"""
        await self.stop()

    async def start(self):
        """Запуск мониторинга"""
        try:
            # Получаем все интерфейсы системы
            all_interfaces = await self.get_all_interfaces()
            
            # Фильтруем только сконфигурированные интерфейсы
            configured_interfaces = self._get_configured_interfaces(all_interfaces)
            filtered_interfaces = [iface for iface in all_interfaces if iface in configured_interfaces]
            
            self._known_interfaces = {
                iface: await self.get_interface_info(iface)
                for iface in filtered_interfaces
            }

            self.logger.info("Инициализация мониторинга сетевых интерфейсов. Обнаружены интерфейсы:")
            for iface, info in self._known_interfaces.items():
                if not info:
                    continue
                status = 'Активен' if info.get('flags', {}).get('up') and info.get('flags', {}).get('running') else 'Неактивен'
                
                # Безопасное получение IPv4 адресов
                ipv4_addresses = []
                if info.get('ipv4') and isinstance(info['ipv4'], dict):
                    addresses = info['ipv4'].get('addresses', [])
                    if addresses and isinstance(addresses, list):
                        ipv4_addresses = [addr.get('address', '') for addr in addresses if isinstance(addr, dict)]
                ipv4_info = f"IPv4: {', '.join(ipv4_addresses)}" if ipv4_addresses else "IPv4: Нет"
                
                # Безопасное получение IPv6 адресов
                ipv6_addresses = []
                if info.get('ipv6') and isinstance(info['ipv6'], list):
                    ipv6_addresses = [addr.get('address', '') for addr in info['ipv6'] if isinstance(addr, dict)]
                ipv6_info = f"IPv6: {', '.join(ipv6_addresses)}" if ipv6_addresses else "IPv6: Нет"
                
                mac_info = f"MAC: {info.get('mac', 'Нет')}"
                self.logger.info(f"Интерфейс: {iface} | {ipv4_info} | {ipv6_info} | {mac_info} | Статус: {status}")

                # Инициализируем множества IP-адресов для интерфейса
                self.interface_ipv4[iface] = set()
                self.interface_ipv6[iface] = set()

                # Добавляем только разрешенные IP-адреса с проверками
                ipv4_data = info.get('ipv4', {})
                if isinstance(ipv4_data, dict):
                    addresses = ipv4_data.get('addresses', [])
                    if isinstance(addresses, list):
                        for addr in addresses:
                            if isinstance(addr, dict) and 'address' in addr:
                                if self._should_monitor_ip(iface, addr['address']):
                                    self.interface_ipv4[iface].add(addr['address'])

                # Добавляем IPv6 адреса с проверками
                ipv6_data = info.get('ipv6', [])
                if isinstance(ipv6_data, list):
                    for addr in ipv6_data:
                        if isinstance(addr, dict) and 'address' in addr:
                            if self._should_monitor_ip(iface, addr['address']):
                                self.interface_ipv6[iface].add(addr['address'])

        except Exception as e:
            self.logger.error(f"Ошибка при старте мониторинга: {str(e)}")
            raise

    async def stop(self):
        """Graceful shutdown"""
        self._running = False
        self.logger.info("Остановка мониторинга сетевых интерфейсов")
        await asyncio.sleep(0.1)  # Даем время на завершение текущих операций

    async def monitor_interfaces_changes(self):
        """Асинхронный мониторинг изменений в списке интерфейсов"""
        try:
            while self._running:
                try:
                    await self._check_interfaces()
                    await asyncio.sleep(self._check_interval)
                except Exception as e:
                    self.logger.error(f"Ошибка при мониторинге интерфейсов: {str(e)}")
                    await asyncio.sleep(1)
        except Exception as e:
            self.logger.error(f"Критическая ошибка в мониторинге интерфейсов: {str(e)}")

    async def _check_interfaces(self):
        """Проверка изменений в интерфейсах"""
        all_interfaces = await self.get_all_interfaces()
        # Фильтруем только сконфигурированные интерфейсы
        configured_interfaces = self._get_configured_interfaces(all_interfaces)
        current_interfaces = [iface for iface in all_interfaces if iface in configured_interfaces]

        current_states = {
            iface: await self.get_interface_info(iface)
            for iface in current_interfaces
        }

        # Обновляем IP-адреса для каждого интерфейса
        self.interface_ipv4.clear()
        self.interface_ipv6.clear()
        
        for iface, state in current_states.items():
            if not state:
                continue

            # Инициализируем множества для текущего интерфейса
            self.interface_ipv4[iface] = set()
            self.interface_ipv6[iface] = set()
            
            # Добавляем IPv4 адреса с проверками
            ipv4_data = state.get('ipv4', {})
            if isinstance(ipv4_data, dict):
                addresses = ipv4_data.get('addresses', [])
                if isinstance(addresses, list):
                    for addr in addresses:
                        if isinstance(addr, dict) and 'address' in addr:
                            ip = addr['address']
                            if self._should_monitor_ip(iface, ip):
                                self.interface_ipv4[iface].add(ip)
            
            # Добавляем IPv6 адреса с проверками
            ipv6_data = state.get('ipv6', [])
            if isinstance(ipv6_data, list):
                for addr in ipv6_data:
                    if isinstance(addr, dict) and 'address' in addr:
                        ip = addr['address']
                        if self._should_monitor_ip(iface, ip):
                            self.interface_ipv6[iface].add(ip)

        # Проверяем новые интерфейсы
        new_interfaces = set(current_interfaces) - set(self._known_interfaces.keys())
        if new_interfaces:
            self.logger.info(f"Обнаружены новые интерфейсы:")
            for iface in new_interfaces:
                if current_states[iface]:
                    status = 'Активен' if current_states[iface].get('flags', {}).get('up') and current_states[iface].get('flags', {}).get('running') else 'Неактивен'
                    ipv4_info = f"IPv4: {', '.join(addr['address'] for addr in current_states[iface].get('ipv4', {}).get('addresses', []))}" if current_states[iface].get('ipv4') else "IPv4: Нет"
                    ipv6_addrs = [addr['address'] for addr in current_states[iface].get('ipv6', [])]
                    ipv6_info = f"IPv6: {', '.join(ipv6_addrs)}" if ipv6_addrs else "IPv6: Нет"
                    mac_info = f"MAC: {current_states[iface].get('mac', 'Нет')}"
                    self.logger.info(f"Интерфейс: {iface} | {ipv4_info} | {ipv6_info} | {mac_info} | Статус: {status}")

        # Проверяем удаленные интерфейсы
        removed_interfaces = set(self._known_interfaces.keys()) - set(current_interfaces)
        if removed_interfaces:
            self.logger.warning(f"Отключены интерфейсы: {', '.join(removed_interfaces)}")

        # Проверяем изменения в существующих интерфейсах
        for iface in set(current_interfaces) & set(self._known_interfaces.keys()):
            if (self._known_interfaces[iface] != current_states[iface] and 
                current_states[iface] is not None):
                self.logger.info(f"Изменения в интерфейсе {iface}:")
                old_info = self._known_interfaces[iface]
                new_info = current_states[iface]
                
                # Проверяем изменения IP адресов
                await self._check_ip_changes(iface, old_info, new_info)
                
                # Проверяем статус
                if old_info.get('flags', {}).get('up') != new_info.get('flags', {}).get('up'):
                    old_status = 'Активен' if old_info['flags'].get('up') else 'Неактивен'
                    new_status = 'Активен' if new_info['flags'].get('up') else 'Неактивен'
                    self.logger.info(f"Статус: {old_status} → {new_status}")

                # Проверяем статистику
                if old_info.get('stats') != new_info.get('stats'):
                    old_rx = old_info['stats'].get('rx_bytes', 0) / (1024 * 1024)
                    old_tx = old_info['stats'].get('tx_bytes', 0) / (1024 * 1024)
                    new_rx = new_info['stats'].get('rx_bytes', 0) / (1024 * 1024)
                    new_tx = new_info['stats'].get('tx_bytes', 0) / (1024 * 1024)
                    self.logger.info(f"Статистика: ↓{old_rx:.2f}MB→{new_rx:.2f}MB ↑{old_tx:.2f}MB→{new_tx:.2f}MB")

        self._known_interfaces = current_states

    def _should_monitor_ip(self, interface: str, ip: str) -> bool:
        """Проверяет, нужно ли отслеживать данный IP-адрес согласно конфигурации"""
        if self.monitoring_config == 'all':
            return True
            
        if isinstance(self.monitoring_config, list):
            for item in self.monitoring_config:
                if isinstance(item, dict) and interface in item:
                    config = item[interface]
                    # Если значение None или пустой словарь, проверяем только интерфейс
                    if config is None or config == {}:
                        return True
                    # Если значение 'all', принимаем все IP для этого интерфейса
                    if config == 'all':
                        return True
                    # Проверяем списки include и exclude
                    if isinstance(config, dict):
                        includes = config.get('include', [])
                        excludes = config.get('exclude', [])
                        
                        # Если IP в списке исключений - пропускаем
                        if ip in excludes:
                            return False
                            
                        # Если список включений пуст или IP в списке включений
                        if not includes or ip in includes:
                            return True
                            
                        return False
            # Если интерфейс не найден в конфигурации
            return False
        
        return False

    async def get_all_interfaces(self) -> List[str]:
        """Получение списка всех сетевых интерфейсов"""
        try:
            loop = asyncio.get_event_loop()
            interfaces = await loop.run_in_executor(None, self._get_interfaces_sync)
            return [iface for iface in interfaces if self._filter_interface(iface)]
        except Exception as e:
            self.logger.error(f"Ошибка получения списка интерфейсов: {str(e)}")
            return []

    def _filter_interface(self, iface: str) -> bool:
        """Фильтрация интерфейсов согласно конфигурации"""
        # Игнорируем loopback интерфейс
        if iface == 'lo':
            return False
            
        # Проверяем настройки мониторинга из конфигурации
        monitoring = getattr(self.config, 'monitoring', {})
        
        # Если интерфейс явно указан в конфигурации
        if iface in monitoring:
            return True
            
        # Если интерфейс не указан в конфигурации, не мониторим его
        return False

    async def get_interface_info(self, ifname: str) -> Optional[dict]:
        """Получение информации об интерфейсе с кэшированием"""
        cache_key = f"if_info_{ifname}"
        cached = self._cache.get(cache_key)
        if cached and time.time() - cached['timestamp'] < self._cache_ttl:
            return cached['data']

        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, self._get_interface_info_sync, ifname)
            if info:
                self._cache[cache_key] = {
                    'timestamp': time.time(),
                    'data': info
                }
            return info
        except Exception as e:
            self.logger.error(f"Ошибка получения информации для {ifname}: {str(e)}")
            return None

    def _get_interface_info_sync(self, ifname: str) -> Optional[dict]:
        """Получение полной информации об интерфейсе"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                info = {
                    'ipv4': self._get_ipv4_info(ifname),
                    'ipv6': self._get_ipv6_addresses(ifname),
                    'mac': self._get_mac_address(ifname),
                    'flags': self._get_interface_flags(s, ifname),
                    # 'stats': self._get_interface_stats(ifname)
                }
                return info
        except Exception as e:
            self.logger.debug(f"Ошибка получения информации для {ifname}: {str(e)}")
            return None

    def _get_ipv4_info(self, ifname: str) -> Optional[Dict[str, Any]]:
        """
        Получение информации об IPv4 адресах интерфейса
        
        Используется команда ip addr show <ifname>, из которой выделяются
        IPv4 адреса вместе с маской, широковещательным адресом и адресом сети.
        
        Возвращает словарь с информацией о IPv4 адресах интерфейса, включая
        список всех адресов, а также "основной" адрес (первый в списке).
        
        Returns:
            Optional[Dict[str, Any]]: Информация об IPv4 адресах интерфейса
        """
        try:
            # Получаем все IP адреса через ip addr
            cmd = f"ip addr show {ifname}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            if result.returncode != 0:
                return None

            ipv4_addresses = []
            for line in result.stdout.splitlines():
                if "inet " in line:  # Ищем IPv4 адреса
                    # Формат: inet 192.168.1.2/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0
                    parts = line.strip().split()
                    ip_with_mask = parts[1]  # 192.168.1.2/24
                    ip, mask = ip_with_mask.split('/')
                    
                    # Вычисляем сеть и широковещательный адрес
                    network = ipaddress.IPv4Network(ip_with_mask, strict=False)
                    broadcast = str(network.broadcast_address)
                    netmask = str(network.netmask)
                    network_addr = str(network.network_address)
                    
                    ipv4_addresses.append({
                        'address': ip,
                        'netmask': netmask,
                        'network': network_addr,
                        'broadcast': broadcast,
                        'prefixlen': int(mask)
                    })

            if not ipv4_addresses:
                return None

            return {
                'addresses': ipv4_addresses,
                'primary': ipv4_addresses[0]  # Первый адрес считаем основным
            }

        except Exception as e:
            self.logger.error(f"Ошибка при получении IPv4 информации для {ifname}: {str(e)}")
            return None

    def _get_ipv6_addresses(self, ifname: str) -> List[dict]:
        """Получение IPv6 адресов интерфейса"""
        try:
            with open(f'/proc/net/if_inet6', 'r') as f:
                ipv6_addrs = []
                for line in f:
                    parts = line.strip().split()
                    if parts[5] == ifname:
                        addr = ':'.join([parts[0][i:i+4] for i in range(0, 32, 4)])
                        scope = int(parts[3], 16)
                        ipv6_addrs.append({
                            'address': addr,
                            'scope': scope,
                            'scope_name': self._get_ipv6_scope_name(scope)
                        })
                return ipv6_addrs
        except Exception:
            return []

    @staticmethod
    def _get_ipv6_scope_name(scope: int) -> str:
        """Получение имени scope для IPv6"""
        scopes = {
            0: 'global',
            1: 'link',
            2: 'site',
            4: 'host',
            5: 'nowhere'
        }
        return scopes.get(scope, 'unknown')

    def _get_mac_address(self, ifname: str) -> Optional[str]:
        """Получение MAC-адреса интерфейса"""
        try:
            with open(f'/sys/class/net/{ifname}/address', 'r') as f:
                return f.read().strip()
        except Exception:
            return None

    def _get_interface_flags(self, sock: socket.socket, ifname: str) -> dict:
        """Получение флагов интерфейса"""
        try:
            flags = struct.unpack('H', fcntl.ioctl(
                sock.fileno(),
                0x8913,  # SIOCGIFFLAGS
                struct.pack('256s', ifname.encode()[:15])
            )[16:18])[0]
            
            return {
                'up': bool(flags & 1),  # IFF_UP
                'broadcast': bool(flags & 2),  # IFF_BROADCAST
                'debug': bool(flags & 4),  # IFF_DEBUG
                'loopback': bool(flags & 8),  # IFF_LOOPBACK
                'pointopoint': bool(flags & 16),  # IFF_POINTOPOINT
                'running': bool(flags & 64),  # IFF_RUNNING
                'noarp': bool(flags & 128),  # IFF_NOARP
                'promisc': bool(flags & 256),  # IFF_PROMISC
                'multicast': bool(flags & 4096)  # IFF_MULTICAST
            }
        except Exception:
            return {}

    def _get_interface_stats(self, ifname: str) -> dict:
        """Получение статистики интерфейса"""
        try:
            with open(f'/proc/net/dev', 'r') as f:
                for line in f:
                    if ifname in line:
                        data = line.split(':')[1].split()
                        return {
                            'rx_bytes': int(data[0]),
                            'rx_packets': int(data[1]),
                            'rx_errors': int(data[2]),
                            'rx_dropped': int(data[3]),
                            'tx_bytes': int(data[8]),
                            'tx_packets': int(data[9]),
                            'tx_errors': int(data[10]),
                            'tx_dropped': int(data[11])
                        }
            return {}
        except Exception:
            return {}

    def _get_interfaces_sync(self) -> List[str]:
        """Синхронное получение списка всех интерфейсов"""
        interfaces = []
        try:
            # Используем /sys/class/net для получения списка интерфейсов
            with os.scandir('/sys/class/net/') as entries:
                for entry in entries:
                    if entry.is_dir():
                        # Проверяем, что интерфейс существует и активен
                        try:
                            with open(f'/sys/class/net/{entry.name}/operstate') as f:
                                state = f.read().strip()
                                if state in ('up', 'unknown'):  # unknown для некоторых виртуальных интерфейсов
                                    interfaces.append(entry.name)
                        except Exception:
                            continue
            return interfaces
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании интерфейсов: {str(e)}")
            return []

    async def _check_ip_changes(self, iface: str, old_info: dict, new_info: dict):
        """Проверка изменений IP адресов на интерфейсе"""
        changes = []
        
        # Проверяем изменения IPv4
        old_ipv4 = old_info.get('ipv4', {})
        new_ipv4 = new_info.get('ipv4', {})
        
        if old_ipv4.get('addresses') != new_ipv4.get('addresses'):
            changes.append({
                'type': 'ipv4',
                'event': 'change',
                'old': old_ipv4.get('addresses', []),
                'new': new_ipv4.get('addresses', []),
                'details': {
                    'old_primary': old_ipv4.get('primary', {}).get('address'),
                    'new_primary': new_ipv4.get('primary', {}).get('address')
                }
            })
        
        # Проверяем изменения IPv6
        old_ipv6 = set(addr['address'] for addr in old_info.get('ipv6', []))
        new_ipv6 = set(addr['address'] for addr in new_info.get('ipv6', []))
        
        added_ipv6 = new_ipv6 - old_ipv6
        removed_ipv6 = old_ipv6 - new_ipv6
        
        for addr in added_ipv6:
            changes.append({
                'type': 'ipv6',
                'event': 'add',
                'address': addr
            })
        
        for addr in removed_ipv6:
            changes.append({
                'type': 'ipv6',
                'event': 'remove',
                'address': addr
            })
        
        if changes:
            await self._notify_ip_changes(iface, changes)

    async def _notify_ip_changes(self, iface: str, changes: List[dict]):
        """Уведомление об изменениях IP адресов"""
        for change in changes:
            if change['type'] == 'ipv4':
                if change['event'] == 'change':
                    self.logger.info(
                        f"Интерфейс: {iface} | Изменение IPv4: {', '.join(addr['address'] for addr in change['old'])} → {', '.join(addr['address'] for addr in change['new'])} | "
                        f"Основной: {change['details']['old_primary']} → {change['details']['new_primary']}"
                    )
            elif change['type'] == 'ipv6':
                if change['event'] == 'add':
                    self.logger.info(f"Интерфейс: {iface} | Добавлен IPv6: {change['address']}")
                elif change['event'] == 'remove':
                    self.logger.info(f"Интерфейс: {iface} | Удален IPv6: {change['address']}")
        
        # Если есть детектор событий, отправляем ему информацию
        if self.detector:
            try:
                await self.detector.handle_ip_changes(iface, changes)
            except Exception as e:
                self.logger.error(f"Ошибка при отправке уведомления детектору: {str(e)}")

    def _get_configured_interfaces(self, available_interfaces=None) -> set:
        """Получение списка интерфейсов из конфигурации"""
        if self.monitoring_config == 'all':
            if available_interfaces is not None:
                return set(available_interfaces)
            return set(self._known_interfaces.keys())
            
        configured_interfaces = set()
        if isinstance(self.monitoring_config, list):
            for item in self.monitoring_config:
                if isinstance(item, dict):
                    configured_interfaces.update(item.keys())
        return configured_interfaces
