import logging
from colorama import init, Fore, Style

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    
    LEVEL_COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        formatter = logging.Formatter(f"{color}%(asctime)s - [%(levelname)s] - %(message)s{Style.RESET_ALL}")
        return formatter.format(record)

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("SecurityAuditor")
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setFormatter(ColoredFormatter())
        logger.addHandler(ch)
        
    return logger
