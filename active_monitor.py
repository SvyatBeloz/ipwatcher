#!/usr/bin/env python3
import asyncio
import socket
import struct
import logging
import time
from typing import List, Dict, Optional
import gc
from monitoring import NetworkMonitor

class ActiveMonitor(NetworkMonitor):
    def __init__(self, config, logger: logging.Logger, detector):
        super().__init__(config, logger, detector)
        self._sockets: Dict[str, socket.socket] = {}  # Сокеты для каждого интерфейса
        self._active_interval = getattr(config, 'active_interval', 30)  # Интервал проверки в секундах
        self._timeout = getattr(config, 'socket_timeout', 7)  # Таймаут для сокетов
        self._batch_size = getattr(config, 'batch_size', 10)  # Количество одновременных запросов

    async def start_active_monitor(self):
        """Запуск активного мониторинга"""
        if not self._running:
            await super().start()
            
        if not self.config.active_enabled:
            self.logger.info("Активный мониторинг отключен в конфигурации")
            return
            
        try:
            # Запускаем только активный мониторинг
            await self.active_monitoring_loop()
        except asyncio.CancelledError:
            self.logger.info("Получен сигнал остановки активного мониторинга")
        except Exception as e:
            self.logger.error(f"Ошибка в активном мониторинге: {str(e)}")
        finally:
            self._close_sockets()

    async def start_passive_monitor(self):
        """Запуск пассивного мониторинга ARP-пакетов"""
        if not self._running:
            self._running = True
            self.logger.info("Запуск пассивного ARP мониторинга...")
            
            try:
                # Создаем сокеты для каждого интерфейса
                for iface in self._interfaces:
                    if iface not in self._sockets:
                        sock = self._get_socket(iface)
                        if not sock:
                            continue
                
                # Запускаем прослушивание для каждого интерфейса
                tasks = []
                for iface, sock in self._sockets.items():
                    tasks.append(self._listen_arp(sock, iface))
                
                await asyncio.gather(*tasks)
                    
            except Exception as e:
                self.logger.error(f"Ошибка при запуске пассивного мониторинга: {str(e)}")
                self._running = False

    def _close_sockets(self):
        """Закрытие всех открытых сокетов"""
        for sock in self._sockets.values():
            try:
                sock.close()
            except Exception as e:
                self.logger.debug(f"Ошибка при закрытии сокета: {str(e)}")
        self._sockets.clear()

    def _get_socket(self, iface: str) -> Optional[socket.socket]:
        """Получение или создание сокета для интерфейса"""
        if iface in self._sockets:
            return self._sockets[iface]
            
        try:
            # Создаем raw сокет для всех протоколов
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # ETH_P_ALL
            sock.bind((iface, 0))
            sock.settimeout(self._timeout)
            self._sockets[iface] = sock
            return sock
        except Exception as e:
            self.logger.error(f"Ошибка создания сокета для {iface}: {str(e)}")
            return None

    def _create_arp_packet(self, src_mac: str, src_ip: str, dst_ip: str) -> bytes:
        """Создание ARP пакета"""
        try:
            # Преобразуем MAC адреса в байты
            src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))
            broadcast_mac = b'\xff' * 6
            
            # Преобразуем IP адреса в байты
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)
            
            # Ethernet заголовок
            eth_header = broadcast_mac + src_mac_bytes + struct.pack('!H', 0x0806)
            
            # ARP заголовок
            arp_header = struct.pack('!HHBBH',
                0x0001,  # Hardware type: Ethernet
                0x0800,  # Protocol type: IPv4
                6,       # Hardware size
                4,       # Protocol size
                0x0001   # Opcode: request
            )
            
            # ARP данные
            arp_data = (
                src_mac_bytes +   # Sender MAC
                src_ip_bytes +    # Sender IP
                broadcast_mac +   # Target MAC
                dst_ip_bytes      # Target IP
            )
            
            return eth_header + arp_header + arp_data
        except Exception as e:
            self.logger.error(f"Ошибка создания ARP пакета: {str(e)}")
            return b''

    def _extract_sender_mac(self, packet: bytes, expected_ip: str) -> Optional[str]:
        """Извлечение MAC адреса отправителя из ARP ответа"""
        try:
            # Проверяем длину пакета
            if len(packet) < 42:  # Минимальная длина ARP пакета
                return None
                
            # Проверяем, что это ARP-ответ
            # Ethernet type (bytes 12-13) должен быть 0x0806 (ARP)
            if packet[12:14] != b'\x08\x06':
                return None
                
            # Проверяем, что это ARP-ответ (opcode = 2)
            if packet[20:22] != b'\x00\x02':
                return None
                
            # Проверяем IP-адрес отправителя (позиция 28-32)
            sender_ip = socket.inet_ntoa(packet[28:32])
            if sender_ip != expected_ip:
                return None
                
            # MAC адрес отправителя в ARP находится в позиции 22-28
            sender_mac = packet[22:28]
            return ':'.join(f'{b:02x}' for b in sender_mac)
        except Exception as e:
            self.logger.error(f"Ошибка при извлечении MAC-адреса: {str(e)}")
            return None

    async def active_monitoring_loop(self):
        """Основной цикл активного мониторинга"""
        while self._running:
            try:
                # Для каждого интерфейса и его отфильтрованных IP адресов
                for iface, ips in self.interface_ipv4.items():
                    sock = self._get_socket(iface)
                    if not sock:
                        continue

                    # Получаем MAC-адрес интерфейса
                    iface_mac = self._known_interfaces[iface]['mac']
                    
                    # Создаем семафор для ограничения одновременных запросов
                    sem = asyncio.Semaphore(self._batch_size)
                    
                    # Отправляем ARP-запросы для каждого IP из отфильтрованного списка
                    tasks = []
                    for src_ip in ips:
                        task = asyncio.create_task(self._check_ip(
                            sem, sock, iface, src_ip, src_ip, iface_mac
                        ))
                        tasks.append(task)
                    
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        
                await asyncio.sleep(self._active_interval)
                
            except Exception as e:
                self.logger.error(f"Ошибка в цикле активного мониторинга: {str(e)}")
                await asyncio.sleep(1)

    async def _check_ip(self, sem: asyncio.Semaphore, sock: socket.socket, 
                       iface: str, src_ip: str, dst_ip: str, src_mac: str):
        """Проверка одного IP адреса"""
        try:
            async with sem:
                self.logger.debug(f"Отправка ARP запроса: {dst_ip} (src: {src_ip}) на интерфейсе {iface}")
                
                # Создаем и отправляем ARP запрос
                arp_packet = self._create_arp_packet(src_mac, src_ip, dst_ip)
                sock.send(arp_packet)
                
                # Ждем ответ
                start_time = time.time()
                got_response = False
                
                while time.time() - start_time < self._timeout:
                    try:
                        response = await asyncio.get_event_loop().run_in_executor(
                            None, sock.recv, 2048
                        )
                        
                        if response:
                            sender_mac = self._extract_sender_mac(response, dst_ip)
                            if sender_mac:  # Проверяем что это валидный ARP-ответ
                                self.logger.info(
                                    f"Получен ARP-ответ: {dst_ip} доступен на интерфейсе {iface} с MAC-адресом {sender_mac} (ARP Reply)"
                                )
                                got_response = True
                                # Продолжаем слушать, возможно будут еще ответы
                    except socket.timeout:
                        continue
                        
                if not got_response:
                    self.logger.debug(f"Нет ответа от {dst_ip}")
                    
        except Exception as e:
            self.logger.error(f"Ошибка при проверке IP {dst_ip} на {iface}: {str(e)}")

    async def _listen_arp(self, sock: socket.socket, iface: str):
        """Прослушивание ARP-пакетов на интерфейсе"""
        try:
            while self._running:
                try:
                    packet = await asyncio.get_event_loop().run_in_executor(
                        None, sock.recv, 2048
                    )
                    
                    if packet:
                        # Проверяем, что это ARP
                        if len(packet) >= 14 and packet[12:14] == b'\x08\x06':
                            # Получаем тип ARP-пакета (1 - request, 2 - reply)
                            arp_type = int.from_bytes(packet[20:22], byteorder='big')
                            
                            # Получаем IP и MAC адреса
                            sender_mac = ':'.join(f'{b:02x}' for b in packet[22:28])
                            sender_ip = socket.inet_ntoa(packet[28:32])
                            target_mac = ':'.join(f'{b:02x}' for b in packet[32:38])
                            target_ip = socket.inet_ntoa(packet[38:42])
                            
                            # Логируем информацию о пакете
                            if arp_type == 1:  # ARP Request
                                self.logger.info(
                                    f"ARP Request на {iface}: кто имеет {target_ip}? "
                                    f"Сообщите {sender_ip} ({sender_mac})"
                                )
                            elif arp_type == 2:  # ARP Reply
                                self.logger.info(
                                    f"ARP Reply на {iface}: {sender_ip} находится на {sender_mac}"
                                )
                            
                            # Уведомляем детектор о новом ARP-пакете
                            if self._detector:
                                await self._detector.process_arp(
                                    iface, sender_ip, sender_mac, 
                                    target_ip, target_mac, arp_type
                                )
                                
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Ошибка при прослушивании ARP на {iface}: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Критическая ошибка в _listen_arp для {iface}: {str(e)}")