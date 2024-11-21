# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class PrinterController:
    def __init__(self, printer):
        self.printer = printer

    # This method overrides the print() method from the Printer interface,
    # but instead of providing an implementation, it calls upon the
    # class passed through the constructor. This is the delegate.
    def print(self, message: str) -> None:
        self.printer.print(message)
