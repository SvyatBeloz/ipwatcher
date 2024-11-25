#!/usr/bin/env python3
import time
import logging
import asyncio
import concurrent.futures
from typing import List, Tuple, Optional
from scapy.all import Ether, ARP, srp, conf
import netifaces
import nmap

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
        for iface in self.config.monitoring:
            interfaces.append(iface)
            self.logger.debug(f"Добавлен интерфейс {iface} для активного мониторинга")
        return interfaces




    async def send_arp_request(
        self, 
        dest_ip: str, 
        interface: str = None,
        src_mac: str = None,
        src_ip: str = None,
        dst_mac: str = "ff:ff:ff:ff:ff:ff",
        timeout: float = 2
    ) -> Tuple[bool, Optional[str]]:
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
            Tuple[bool, Optional[str]]: (успех, MAC адрес)
                - Если устройство ответило: (True, 'mac:address')
                - Если устройство не ответило: (False, None)
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

            self.logger.debug(f"Отправка ARP запроса для {dest_ip} через интерфейс {interface or 'default'}")
            
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
                # Получаем MAC адрес из первого ответа
                mac = result[0][1].hwsrc
                self.logger.debug(f"Получен ответ от {dest_ip}: MAC={mac}")
                return True, mac
            
            self.logger.debug(f"Нет ответа от {dest_ip}")
            return False, None

        except Exception as e:
            self.logger.error(f"Ошибка при отправке ARP запроса для {dest_ip}: {str(e)}")
            return False, None

    async def send_gratuitous_arp(self, interface: str, src_ip: str = None) -> Tuple[bool, Optional[str]]:
        """
        Отправляет Gratuitous ARP запрос и ждет ответа
        
        Args:
            interface (str): Сетевой интерфейс
            src_ip (str): IP адрес интерфейса (если не указан, будет получен автоматически)
            
        Returns:
            Tuple[bool, Optional[str]]: (успех, MAC адрес ответившего устройства)
        """
        try:
            # Получаем IP адрес интерфейса если не указан
            if not src_ip:
                addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
                if not addrs:
                    self.logger.error(f"Не удалось получить IP адрес для интерфейса {interface}")
                    return False, None
                src_ip = addrs[0]['addr']
            
            # Получаем MAC адрес интерфейса
            link_info = netifaces.ifaddresses(interface).get(netifaces.AF_LINK)
            if not link_info:
                self.logger.error(f"Не удалось получить MAC адрес для интерфейса {interface}")
                return False, None
                
            mac = link_info[0]['addr']
            
            # Создаем Gratuitous ARP пакет
            # pdst равен psrc для Gratuitous ARP
            arp = ARP(
                op=1,  # ARP request
                hwsrc=mac,
                psrc=src_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=src_ip
            )
            
            # Создаем Ethernet фрейм
            ether = Ether(
                src=mac,
                dst="ff:ff:ff:ff:ff:ff"
            )
            
            packet = ether/arp
            
            self.logger.debug(f"Отправка Gratuitous ARP для {interface} (IP: {src_ip}, MAC: {mac})")
            
            # Отправляем пакет и получаем ответы
            ans, unans = await asyncio.to_thread(
                lambda: srp(
                    packet,
                    timeout=1,
                    verbose=False,
                    iface=interface
                )
            )
            
            # Проверяем ответы
            if ans:
                # Получаем MAC адрес из первого ответа
                response_mac = ans[0][1].hwsrc
                response_ip = ans[0][1].psrc
                self.logger.debug(f"Получен ответ на Gratuitous ARP: IP={response_ip}, MAC={response_mac}")
                return True, response_mac
            
            self.logger.debug(f"Нет ответов на Gratuitous ARP для {src_ip}")
            return False, None
            
        except Exception as e:
            self.logger.error(f"Ошибка при отправке Gratuitous ARP для {interface}: {str(e)}")
            return False, None

    def _get_active_ips(self, iface_ip: str) -> List[str]:
        """
        Получает список активных IP адресов в сети с помощью nmap
        
        Args:
            iface_ip (str): IP адрес интерфейса
            
        Returns:
            List[str]: Список активных IP адресов
        """
        try:
            # Получаем подсеть в формате CIDR (например 192.168.1.0/24)
            import ipaddress
            network = ipaddress.IPv4Network(f"{iface_ip}/24", strict=False)
            network_cidr = str(network)
            
            # Запускаем быстрое сканирование nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=network_cidr, arguments='-sn')  # ping scan
            
            # Получаем список активных IP адресов
            active_ips = []
            for host in nm.all_hosts():
                if host != iface_ip:  # Исключаем свой IP
                    active_ips.append(host)
                    
            self.logger.debug(f"Найдено {len(active_ips)} активных хостов в сети {network_cidr}")
            return active_ips
            
        except Exception as e:
            self.logger.error(f"Ошибка при сканировании сети {iface_ip}/24: {str(e)}")
            return []

    async def start(self):
        """
        Запускает активный мониторинг сети, отправляя Gratuitous ARP
        для IP-адресов из конфигурации
        """
        while True:
            for iface in self.interfaces:
                try:
                    # Получаем IP адрес интерфейса
                    addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                    if not addrs:
                        continue
                        
                    iface_ip = addrs[0]['addr']
                    self.logger.debug(f"Мониторинг через интерфейс {iface} (IP: {iface_ip})")
                    
                    # Определяем список IP для Gratuitous ARP
                    if iface in self.config.monitoring:
                        if 'all' in self.config.monitoring[iface]:
                            # Отправляем один Gratuitous ARP от имени интерфейса
                            await self.send_gratuitous_arp(iface, iface_ip)
                        else:
                            # Отправляем Gratuitous ARP для каждого IP из конфига
                            for ip in self.config.monitoring[iface]:
                                await self.send_gratuitous_arp(iface, ip)
                    elif self.config.monitoring == 'all':
                        # Отправляем один Gratuitous ARP от имени интерфейса
                        await self.send_gratuitous_arp(iface, iface_ip)
                            
                except Exception as e:
                    self.logger.error(f"Ошибка при мониторинге интерфейса {iface}: {str(e)}")
            
            await asyncio.sleep(self.config.active_interval)
