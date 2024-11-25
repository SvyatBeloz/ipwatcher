#!/usr/bin/env python3
import logging
from logging.handlers import SysLogHandler
from typing import Optional
from colorama import Fore, Style, init as colorama_init

# Initialize colorama
colorama_init()

# Define log colors
LOG_COLORS = {
    'DEBUG': Fore.CYAN,
    'INFO': Fore.GREEN,
    'WARNING': Fore.YELLOW,
    'ERROR': Fore.RED,
    'CRITICAL': Fore.MAGENTA + Style.BRIGHT
}

class Logger:
    def __init__(self, level: str):
        self.logger = logging.getLogger("IPConflictDetector")
        level = level.upper()  # Преобразуем в верхний регистр
        if not hasattr(logging, level):
            print(f"Неверный уровень логирования: {level}, используется INFO")
            level = "INFO"
        
        self.logger.setLevel(getattr(logging, level))
        self.logger.propagate = False  # Prevent duplicate logs

        # Formatter string с миллисекундами
        formatter_str = '[%(asctime)s.%(msecs)03d] %(levelname)s - %(message)s'
        date_format = '%Y-%m-%dT%H:%M:%S'

        # Console Handler with color
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level))
        console_formatter = self.ColorFormatter(formatter_str, datefmt=date_format)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # SysLog Handler for journalctl
        try:
            syslog_handler = SysLogHandler(address='/dev/log')
            syslog_handler.setLevel(getattr(logging, level))
            syslog_formatter = logging.Formatter(formatter_str, datefmt=date_format)
            syslog_handler.setFormatter(syslog_formatter)
            self.logger.addHandler(syslog_handler)
        except Exception as e:
            print(f"Не удалось настроить syslog: {e}")

        self.logger.debug("Логгер инициализирован")

    class ColorFormatter(logging.Formatter):
        def __init__(self, fmt: str, datefmt: Optional[str] = None):
            super().__init__(fmt, datefmt)

        def format(self, record):
            log_color = LOG_COLORS.get(record.levelname, "")
            reset = Style.RESET_ALL
            if record.msg:
                record.msg = f"{log_color}{record.msg}{reset}"
            return super().format(record)

    def get_logger(self):
        return self.logger
