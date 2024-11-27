#!/usr/bin/env python3
import time
import logging
import asyncio
from typing import List, Tuple, Optional
from pyroute2 import IPRoute, NDB
import ipaddress
import gc
from monitoring import IPMonitor

class ActiveMonitor(IPMonitor):

    async def start(self):
        """Основной цикл мониторинга интерфейсов."""
        try:
            while True:
                # Создаем и выполняем задачи
                tasks = []
                for iface in self.interfaces:
                    task = asyncio.create_task(self.monitor_interface(iface))
                    tasks.append(task)
                
                # Ждем выполнения всех задач
                await asyncio.gather(*tasks)
                
                # Очищаем задачи и память
                for task in tasks:
                    task.cancel()
                tasks.clear()
                del tasks
                gc.collect()
                
                # Ждем следующего цикла
                await asyncio.sleep(self.config.active_interval)
        except Exception as e:
            self.logger.error(f"Ошибка в основном цикле мониторинга: {str(e)}")
        finally:
            gc.collect()
    
    def get_interfaces(self) -> List[str]:
        """
        Получает список интерфейсов для активного мониторинга используя pyroute2.NDB
        """
        interfaces = []
        monitoring_config = self.config.monitoring
        
        with NDB() as ndb:
            # Получаем список всех интерфейсов
            all_interfaces = [iface.ifname for iface in ndb.interfaces.dump()
                            if iface.state == 'up']
            gc.collect()  # После получения списка интерфейсов
            
            # Если monitoring = "all", получаем все доступные интерфейсы
            if monitoring_config == "all":
                interfaces = all_interfaces
            # Если monitoring - это список или словарь с конфигурацией интерфейсов
            elif isinstance(monitoring_config, (list, dict)):
                if isinstance(monitoring_config, list):
                    # Проверяем существование интерфейсов из списка
                    interfaces.extend([iface for iface in monitoring_config 
                                    if iface in all_interfaces])
                else:
                    # Проверяем существование интерфейсов из ключей словаря
                    interfaces.extend([iface for iface in monitoring_config.keys() 
                                    if iface in all_interfaces])
                
        self.logger.debug(f"Интерфейсы для активного мониторинга: {interfaces}")
        gc.collect()  # После формирования списка интерфейсов
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
        Асинхронно отправляет ARP запрос для указанного IP адреса используя NDB
        
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
            # Создаем NDB объект
            with NDB() as ndb:
                # Если интерфейс не указан, используем маршрут по умолчанию
                if not interface:
                    routes = ndb.routes.dump().filter(dst='default')
                    if not routes:
                        self.logger.error("Не найден маршрут по умолчанию")
                        gc.collect()  # После работы с маршрутами
                        return False, None
                    interface = routes[0].get_attr('RTA_OIF')
                    gc.collect()  # После получения маршрута

                # Получаем информацию об интерфейсе
                iface_data = ndb.interfaces.dump().filter(ifname=interface)
                if not iface_data:
                    self.logger.error(f"Интерфейс {interface} не найден")
                    gc.collect()  # После работы с интерфейсами
                    return False, None

                with IPRoute() as ipr:
                    # Получаем индекс интерфейса
                    idx = ipr.link_lookup(ifname=interface)[0]
                    
                    # Если src_mac не указан, получаем его из интерфейса
                    if not src_mac:
                        links = ipr.get_links(idx)
                        if links:
                            src_mac = links[0].get_attr('IFLA_ADDRESS')
                    gc.collect()  # После получения MAC адреса
                    
                    # Если src_ip не указан, получаем его из интерфейса
                    if not src_ip:
                        addrs = [addr.get_attr('IFA_LOCAL') 
                                for addr in ipr.get_addr()
                                if addr.get('index', None) == idx and addr['family'] == 2]
                        if addrs:
                            src_ip = addrs[0]
                    gc.collect()  # После получения IP адреса

                    # Очищаем старые ARP записи для целевого IP
                    try:
                        neighbours = ipr.get_neighbours(dst=dest_ip)
                        for neigh in neighbours:
                            ipr.neigh('del', 
                                    dst=neigh.get_attr('NDA_DST'),
                                    lladdr=neigh.get_attr('NDA_LLADDR'),
                                    ifindex=idx)
                        gc.collect()  # После очистки ARP кэша
                    except Exception as e:
                        self.logger.debug(f"Ошибка при очистке ARP кэша: {str(e)}")

                    # Отправляем ARP запрос
                    try:
                        ipr.neigh('add', 
                                dst=dest_ip,
                                lladdr=dst_mac,
                                ifindex=idx,
                                state=0x80)  # NUD_PROBE
                        gc.collect()  # После отправки ARP запроса
                    except Exception as e:
                        self.logger.debug(f"Ошибка при отправке ARP запроса: {str(e)}")

                    # Ждем ответ
                    await asyncio.sleep(timeout)

                    # Проверяем ARP кэш
                    neighbours = ipr.get_neighbours(dst=dest_ip)
                    mac_addresses = [n.get_attr('NDA_LLADDR') for n in neighbours 
                                   if n.get_attr('NDA_LLADDR') and 
                                   n.get_attr('NDA_LLADDR') != dst_mac]

                    if mac_addresses:
                        self.logger.info(f"Получены ответы от {dest_ip}: MAC адреса={mac_addresses}")
                        gc.collect()  # После получения MAC адресов
                        return True, mac_addresses

                    self.logger.debug(f"Нет ответа от {dest_ip}")
                    gc.collect()  # После завершения проверки
                    return False, None

        except Exception as e:
            self.logger.error(f"Ошибка при отправке ARP запроса для {dest_ip}: {str(e)}")
            gc.collect()  # После обработки ошибки
            return False, None

    async def monitor_interface(self, iface: str):
        """
        Мониторинг конкретного интерфейса.
        Обрабатывает IP-адреса согласно настройкам `include` и `exclude`.
        """
        try:
            addrs = []
            with NDB() as ndb:
                # Получаем информацию об интерфейсе
                iface_data = ndb.interfaces.dump().filter(ifname=iface)
                if not iface_data:
                    self.logger.debug(f"Интерфейс {iface} не найден")
                    return
                
                # Получаем IPv4 адреса интерфейса через IPRoute
                with IPRoute() as ipr:
                    idx = ipr.link_lookup(ifname=iface)[0]
                    
                    # Получаем все адреса для интерфейса
                    all_addrs = ipr.get_addr()
                    
                    # Фильтруем IPv4 адреса для нужного интерфейса 
                    for addr in all_addrs:
                        if (addr.get('index', None) == idx and 
                            addr['family'] == 2 and  
                            addr.get_attr('IFA_LOCAL')):
                            addrs.append(addr.get_attr('IFA_LOCAL'))
                    
                    # Очищаем временные данные
                    del all_addrs
                    gc.collect()
                
            if not addrs:
                self.logger.debug(f"Интерфейс {iface} не имеет IPv4 адреса")
                return
            
            iface_ip = addrs[0]
            monitoring_config = self.config.monitoring
            
            # Определяем IP адреса для мониторинга
            ips_to_monitor = []
            
            if isinstance(monitoring_config, list) or (
                isinstance(monitoring_config, dict) and iface not in monitoring_config):
                ips_to_monitor = await self._get_active_ips(iface_ip)
            else:
                settings = monitoring_config[iface]
                if isinstance(settings, str) and settings == "all":
                    ips_to_monitor = await self._get_active_ips(iface_ip)
                else:
                    include = settings.get("include", "all")
                    exclude = settings.get("exclude", [])
                    if include == "all":
                        ips_to_monitor = await self._get_active_ips(iface_ip)
                    else:
                        ips_to_monitor = include
                    
                    # Исключаем IP адреса
                    if exclude:
                        ips_to_monitor = [ip for ip in ips_to_monitor if ip not in exclude]
            
            # Обрабатываем IP адреса небольшими группами для экономии памяти
            batch_size = 10
            for i in range(0, len(ips_to_monitor), batch_size):
                batch = ips_to_monitor[i:i + batch_size]
                tasks = []
                for ip in batch:
                    task = asyncio.create_task(self.process_ip(iface, ip))
                    tasks.append(task)
                await asyncio.gather(*tasks)
                
                # Очищаем задачи и память после каждой группы
                for task in tasks:
                    task.cancel()
                tasks.clear()
                del tasks
                gc.collect()
            
            # Очищаем оставшиеся данные
            del ips_to_monitor
            del addrs
            gc.collect()

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
            gc.collect()  # После обработки IP адреса
        except Exception as e:
            self.logger.error(f"Ошибка обработки IP {ip} на интерфейсе {iface}: {str(e)}")
            gc.collect()  # После обработки ошибки

    async def _get_active_ips(self, iface_ip: str = None) -> List[str]:
        """
        Получает список активных IP адресов в сети интерфейса.
        
        Args:
            iface_ip (str): IP адрес интерфейса
            
        Returns:
            List[str]: Список активных IP адресов
        """
        if not iface_ip:
            return []

        active_ips = []
        try:
            # Создаем объект сети
            network = ipaddress.IPv4Network(f"{iface_ip}/24", strict=False)
            
            # Получаем только локальные адреса из сети
            with IPRoute() as ipr:
                local_addrs = set()
                for addr in ipr.get_addr():
                    ip = addr.get_attr('IFA_ADDRESS')
                    if ip:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if (ip_obj.version == 4 and 
                                not ip_obj.is_loopback and 
                                ip_obj in network):
                                local_addrs.add(str(ip_obj))
                        except ValueError:
                            continue
                
                # Очищаем неиспользуемые объекты
                gc.collect()
                
                if local_addrs:
                    active_ips.extend(local_addrs)
                    
            self.logger.debug(f"Найдены активные IP-адреса для сети {iface_ip}: {active_ips}")
            
            # Очищаем все временные объекты
            del network
            del local_addrs
            gc.collect()
            
            return active_ips
                
        except Exception as e:
            self.logger.error(f"Ошибка при получении активных IP-адресов: {str(e)}")
            # Очищаем все объекты в случае ошибки
            gc.collect()
            return []
        finally:
            # Финальная очистка
            del active_ips
            gc.collect()
