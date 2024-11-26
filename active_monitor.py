#!/usr/bin/env python3
import time
import logging
import asyncio
import concurrent.futures
from typing import List, Tuple, Optional
from scapy.all import Ether, ARP, srp, conf
import netifaces
import nmap
from pyroute2 import IPRoute
import ipaddress

class ActiveMonitor:
    def __init__(self, config, logger: logging.Logger, detector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()
        # Создаем executor для блокирующих операций
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def get_interfaces(self) -> List[str]:
        """
        Получает список интерфейсов для активного мониторинга
        """
        interfaces = []
        monitoring_config = self.config.monitoring
        
        # Если monitoring = "all", получаем все доступные интерфейсы
        if monitoring_config == "all":
            interfaces = netifaces.interfaces()
        # Если monitoring - это список или словарь с конфигурацией интерфейсов
        elif isinstance(monitoring_config, (list, dict)):
            if isinstance(monitoring_config, list):
                interfaces.extend(monitoring_config)
            else:
                interfaces.extend(monitoring_config.keys())
                
        self.logger.debug(f"Интерфейсы для активного мониторинга: {interfaces}")
        return interfaces




    async def send_arp_request(
        self, 
        dest_ip: str, 
        interface: str = None,
        src_mac: str = None,
        src_ip: str = None,
        dst_mac: str = "ff:ff:ff:ff:ff:ff",
        timeout: float = 2
    ) -> Tuple[bool, Optional[List[str]]]:
        """
        Асинхронно отправляет ARP запрос для указанного IP адреса
        
        Args:
            dest_ip (str): IP адрес устройства назначения
            interface (str): Сетевой интерфейс для отправки запроса (например, "eth0")
            src_mac (str): MAC адрес отправителя
            src_ip (str): IP адрес отправителя
            dst_mac (str): MAC адрес получателя (по умолчанию широковещательный ff:ff:ff:ff:ff:ff)
            timeout (float): Таймаут ожидания ответа в секундах
            
        Returns:
            Tuple[bool, Optional[List[str]]]: (успех, список MAC адресов)
                - Если устройства ответили: (True, ['mac:address1', 'mac:address2', ...])
                - Если устройства не ответили: (False, None)
        """

        try:
            # Создаем ARP запрос с указанными параметрами
            arp_request = ARP(pdst=dest_ip)
            if src_ip:
                arp_request.psrc = src_ip
            
            # Создаем Ethernet фрейм
            ether = Ether(dst=dst_mac)
            if src_mac:
                ether.src = src_mac
                
            packet = ether/arp_request

            self.logger.debug(f"Отправка ARP запроса от {src_ip} для {dest_ip} через интерфейс {interface or 'default'}")
            
            # Выполняем отправку пакета в отдельном потоке
            result = await asyncio.to_thread(
                lambda: srp(
                    packet, 
                    timeout=timeout, 
                    verbose=False,
                    iface=interface
                )[0]
            )

            # Проверяем результат
            if result:
                # Получаем все MAC адреса из ответов
                mac_addresses = [response[1].hwsrc for response in result]
                self.logger.info(f"Получены ответы от {dest_ip}: MAC адреса={mac_addresses}")
                return True, mac_addresses
            
            self.logger.debug(f"Нет ответа от {dest_ip}")
            return False, None

        except Exception as e:
            self.logger.error(f"Ошибка при отправке ARP запроса для {dest_ip}: {str(e)}")
            return False, None




    async def start(self):
        """Основной цикл мониторинга интерфейсов."""
        while True:
            tasks = [self.monitor_interface(iface) for iface in self.interfaces]
            await asyncio.gather(*tasks)
            await asyncio.sleep(self.config.active_interval)

    async def monitor_interface(self, iface: str):
        """
        Мониторинг конкретного интерфейса.
        Обрабатывает IP-адреса согласно настройкам `include` и `exclude`.
        """
        try:
            # Получаем IP адрес интерфейса
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            if not addrs:
                self.logger.debug(f"Интерфейс {iface} не имеет IPv4 адреса")
                return
            
            iface_ip = addrs[0]['addr']
            monitoring_config = self.config.monitoring
            
            # Если monitoring = "all" или интерфейс не указан в конфигурации
            if monitoring_config == "all" or (isinstance(monitoring_config, dict) and iface not in monitoring_config):
                include = await self._get_active_ips(iface_ip)
                exclude = []
            else:
                # Получаем настройки для конкретного интерфейса
                settings = monitoring_config[iface]
                if isinstance(settings, str) and settings == "all":
                    include = await self._get_active_ips(iface_ip)
                    exclude = []
                else:
                    include = settings.get("include", "all")
                    exclude = settings.get("exclude", [])
                    if include == "all":
                        include = await self._get_active_ips(iface_ip)

            # Исключаем адреса из `exclude`
            ips_to_monitor = [ip for ip in include if ip not in exclude]
            
            self.logger.debug(f"Мониторинг интерфейса {iface} ({iface_ip}): {len(ips_to_monitor)} IP адресов")

            # Отправляем запросы для всех подходящих IP
            tasks = [self.process_ip(iface, ip) for ip in ips_to_monitor]
            await asyncio.gather(*tasks)

        except Exception as e:
            self.logger.error(f"Ошибка при мониторинге интерфейса {iface}: {str(e)}")
            self.logger.debug(f"Текущая конфигурация monitoring: {self.config.monitoring}")

    async def process_ip(self, iface: str, ip: str):
        """
        Обработка IP-адреса на интерфейсе.
        Отправляет ARP-запрос и обновляет карту MAC-IP.
        """
        try:
            success, macs = await self.send_arp_request(dest_ip=ip, interface=iface,src_ip=ip)
            if success and macs:
                self.logger.info("у меня хотят украсть ip,где-то двойник")
                # self.detector.update_mapping(iface, ip, mac)
                # self.logger.debug(f"Обновлены MAC-адреса для интерфейса {iface}: {ip} -> {macs}")
        except Exception as e:
            self.logger.error(f"Ошибка обработки IP {ip} на интерфейсе {iface}: {str(e)}")

    async def _get_active_ips(self, iface_ip: str = None) -> List[str]:
        """
        Получает список активных IP-адресов в сети с помощью pyroute2.
        Исключает локальные адреса и адреса Docker-контейнеров.
        
        Args:
            iface_ip (str): IP-адрес интерфейса для определения сети
            
        Returns:
            List[str]: Список активных IP-адресов
        """
        try:
            # Создаем экземпляр IPRoute
            with IPRoute() as ipr:
                active_ips = []
                
                # Получаем индекс интерфейса по IP-адресу
                if iface_ip:
                    network = ipaddress.ip_network(f"{iface_ip}/24", strict=False)
                    
                    # Получаем все адреса из таблицы маршрутизации
                    for addr in ipr.get_addr():
                        attrs = dict(addr['attrs'])
                        if 'IFA_ADDRESS' in attrs:
                            ip = attrs['IFA_ADDRESS']
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                # Проверяем, что IP адрес находится в той же сети
                                if (ip_obj.version == 4 and
                                    not ip_obj.is_loopback and
                                    # not str(ip_obj).startswith('172.') and
                                    # not ip_obj.is_link_local and
                                    ip_obj in network):  # Проверяем, что адрес в той же сети
                                    active_ips.append(str(ip_obj))
                            except ValueError:
                                continue
                
                self.logger.debug(f"Найдены активные IP-адреса для сети {iface_ip}: {active_ips}")
                return active_ips
                
        except Exception as e:
            self.logger.error(f"Ошибка при получении активных IP-адресов: {str(e)}")
            return []
