import logging

class HpPrinter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def print(self, message: str) -> None:
        self.logger.info("HP Printer : %s", message)
