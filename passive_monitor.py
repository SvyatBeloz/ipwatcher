#!/usr/bin/env python3
import logging
import asyncio
from pyroute2 import NDB, IPRoute
import gc
from monitoring import NetworkMonitor

class PassiveMonitor(NetworkMonitor):
    
    async def _monitor_arp_events(self, iface):
        """Мониторинг ARP событий для конкретного интерфейса используя NDB."""
        try:
            with NDB() as ndb:
                # Получаем индекс интерфейса
                idx = ndb.interfaces[iface]['index']
                
                while self._running:
                    # Получаем все текущие записи ARP для интерфейса
                    for record in ndb.neighbours:
                        try:
                            if record['ifindex'] == idx:
                                # Получаем состояние записи
                                state = record['state']
                                # Проверяем только активные записи
                                if state in ('permanent', 'reachable', 'stale', 'delay'):
                                    ip = record['dst']
                                    mac = record['lladdr']
                                    if ip and mac:
                                        self.logger.debug(f"Обнаружено ARP событие на интерфейсе {iface}: IP={ip}, MAC={mac}")
                                        # self.detector.update_mapping(iface, ip, mac)
                        except KeyError as e:
                            # Пропускаем записи без нужных полей
                            continue
                        except Exception as e:
                            self.logger.debug(f"Ошибка обработки записи ARP: {str(e)}")
                    
                    # Ждем перед следующей проверкой
                    gc.collect()
                    await asyncio.sleep(3)
                    
        except Exception as e:
            self.logger.error(f"Ошибка при мониторинге ARP событий на интерфейсе {iface}: {str(e)}")
            gc.collect()

    def start(self):
        """Запуск пассивного мониторинга на всех интерфейсах."""
        self._running = True
        
        # Создаем задачи мониторинга для каждого интерфейса
        for iface in self.interfaces:
            self.logger.info(f"Начало пассивного мониторинга интерфейса {iface}")
            asyncio.create_task(self._monitor_arp_events(iface))
