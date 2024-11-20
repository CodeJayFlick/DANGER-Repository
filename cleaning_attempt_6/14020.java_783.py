import logging

class CanonPrinter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def print(self, message: str) -> None:
        self.logger.info("Canon Printer : %s", message)

if __name__ == "__main__":
    printer = CanonPrinter()
    printer.print("Hello World!")
