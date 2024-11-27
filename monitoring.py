import logging

class IPMonitor:
    def __init__(self, config, logger: logging.Logger, detector):
        self.config = config
        self.logger = logger
        self.detector = detector
        self.interfaces = self.get_interfaces()
    
    async def _monitor_ip_changes(self):
        """
        Мониторинг изменений IP-адресов на интерфейсах с помощью pyroute2.
        """
        try:
            with IPRoute() as ipr:
                # Подписываемся на все события, связанные с адресами (RTM_NEWADDR, RTM_DELADDR)
                ipr.bind()
                
                while True:
                    # Получаем следующее сообщение
                    msg = await asyncio.to_thread(ipr.get)
                    
                    # Обрабатываем только события, связанные с IP-адресами
                    if msg['event'] in ['RTM_NEWADDR', 'RTM_DELADDR']:
                        # Получаем имя интерфейса
                        if_index = msg['index']
                        if_name = None
                        
                        # Получаем имя интерфейса по индексу
                        links = ipr.get_links()
                        for link in links:
                            if link['index'] == if_index:
                                if_attrs = dict(link['attrs'])
                                if_name = if_attrs.get('IFLA_IFNAME')
                                break
                        
                        if if_name and if_name in self.interfaces:
                            event_type = "добавлен" if msg['event'] == 'RTM_NEWADDR' else "удален"
                            attrs = dict(msg['attrs'])
                            if 'IFA_ADDRESS' in attrs:
                                ip = attrs['IFA_ADDRESS']
                                self.logger.info(f"IP-адрес {ip} был {event_type} на интерфейсе {if_name}")
                                
                                # Здесь можно добавить дополнительную логику обработки изменений
                                # Например, обновить список отслеживаемых IP-адресов
                    
                    # Небольшая пауза для предотвращения высокой загрузки CPU
                    # await asyncio.sleep(0.1)
                    gc.collect()  # После обработки сообщения
                    
        except Exception as e:
            self.logger.error(f"Ошибка при мониторинге изменений IP: {str(e)}")
            gc.collect()  # После обработки ошибки
