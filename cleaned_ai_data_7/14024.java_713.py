import unittest
from logging import Logger, getLogger, handlers, Formatter

class DelegateTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()
        logger = getLogger("root")
        logger.addHandler(self.appender)

    def tearDown(self):
        self.appender.stop()

    MESSAGE = "Test Message Printed"

    @unittest.skip
    def test_canon_printer(self):
        printer_controller = PrinterController(CanonPrinter())
        printer_controller.print(MESSAGE)
        self.assertEqual(f"Canon Printer : {MESSAGE}", self.appender.get_last_message())

    @unittest.skip
    def test_hp_printer(self):
        printer_controller = PrinterController(HpPrinter())
        printer_controller.print(MESSAGE)
        self.assertEqual(f"HP Printer : {MESSAGE}", self.appender.get_last_message())

    @unittest.skip
    def test_epson_printer(self):
        printer_controller = PrinterController(EpsonPrinter())
        printer_controller.print(MESSAGE)
        self.assertEqual(f"Epson Printer : {MESSAGE}", self.appender.get_last_message())


class InMemoryAppender(handlers.BaseRotatingFileHandler):

    def __init__(self):
        super().__init__("log.txt", 0, 1)

    def format(self, record):
        return f"{record.levelname} - {record.getMessage()}"


class PrinterController:
    def __init__(self, printer: object):
        self.printer = printer

    def print(self, message: str) -> None:
        self.printer.print(message)


class CanonPrinter:
    def print(self, message: str) -> None:
        pass  # This is a placeholder. The actual implementation should be here


class HpPrinter:
    def print(self, message: str) -> None:
        pass  # This is a placeholder. The actual implementation should be here


class EpsonPrinter:
    def print(self, message: str) -> None:
        pass  # This is a placeholder. The actual implementation should be here
