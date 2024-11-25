#!/usr/bin/env python3
import time
import logging
from typing import List
from scapy.all import Ether, ARP, srp, conf

class ActiveMonitor:
    def __init__(self, config, logger: logging.Logger, detector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()

    def get_interfaces(self) -> List[str]:
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
