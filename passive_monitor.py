#!/usr/bin/env python3
import logging
import threading
from functools import partial
from typing import List
from scapy.all import ARP, sniff, conf

class PassiveMonitor:
    def __init__(self, config, logger: logging.Logger, detector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()
        # Suppress scapy's verbose output
        conf.verb = 0

    def get_interfaces(self) -> List[str]:
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
