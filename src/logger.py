from datetime import datetime
from colorama import Fore

class Logger:
    def __init__(self, prefix: str = "VMCrypt") -> None:
        self.WHITE: str = "\u001b[37m"
        self.MAGENTA: str = "\033[38;5;97m"
        self.MAGENTAA: str = "\033[38;2;157;38;255m"
        self.RED: str = "\033[38;5;196m"
        self.GREEN: str = "\033[38;5;40m"
        self.YELLOW: str = "\033[38;5;220m"
        self.BLUE: str = "\033[38;5;21m"
        self.LIGHTBLUE = Fore.LIGHTBLUE_EX
        self.PINK: str = "\033[38;5;176m"
        self.CYAN: str = "\033[96m"
        self.prefix: str = f"{self.PINK}[{self.MAGENTAA}{prefix}{self.PINK}]"

    @staticmethod
    def get_time() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def message(self, level: str, message: str, start: int = None, end: int = None, hide_chars: int = None) -> str:
        if hide_chars:
            message = f"{message[:hide_chars]}... ({len(message) - hide_chars} more chars)"
        time_now = (f" {self.PINK}[{self.MAGENTAA}{self.get_time()}{self.PINK}] {self.WHITE}|")
        timer = f" {self.MAGENTAA}In{self.WHITE} -> {self.MAGENTAA}{str((end - start) * 1000)[:5]} ms" if start is not None and end is not None else ""
        return f"  {self.prefix} {self.WHITE}|{time_now} {self.PINK}[{level}{self.PINK}] {self.WHITE}-> {self.PINK}[{self.MAGENTA}{message}{self.PINK}]{timer}"

    def success(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "Success") -> None:
        print(self.message(f"{self.GREEN}{level}", f"{self.GREEN}{message}", start, end, hide_chars))

    def warning(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "Warning") -> None:
        print(self.message(f"{self.YELLOW}{level}", f"{self.YELLOW}{message}", start, end, hide_chars))

    def info(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "Info") -> None:
        print(self.message(f"{self.LIGHTBLUE}{level}", f"{self.LIGHTBLUE}{message}", start, end, hide_chars))

    def failure(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "Failure") -> None:
        print(self.message(f"{self.RED}{level}", f"{self.RED}{message}", start, end, hide_chars))

    def debug(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "Debug") -> None:
        print(self.message(f"{self.MAGENTAA}{level}", f"{self.MAGENTAA}{message}", start, end, hide_chars))

    def captcha(self, message: str, start: int = None, end: int = None, hide_chars: int = None, level: str = "hCaptcha") -> None:
        print(self.message(f"{self.CYAN}{level}", f"{self.CYAN}{message}", start, end, hide_chars))

    def input(self, question: str) -> str:
        return input(f"  {self.prefix}{self.WHITE} | {self.PINK}[{self.MAGENTAA}{question}{self.PINK}]{self.WHITE} -> ")



log = Logger()
