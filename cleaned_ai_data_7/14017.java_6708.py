class Printer:
    def print(self):
        pass


class CanonPrinter(Printer):
    def print(self):
        return "Printing with Canon"


class EpsonPrinter(Printer):
    def print(self):
        return "Printing with Epson"


class HpPrinter(Printer):
    def print(self):
        return "Printing with HP"


def main():
    hp_printer = PrinterController(HpPrinter())
    canon_printer = PrinterController(CanonPrinter())
    epson_printer = PrinterController(EpsonPrinter())

    print(hp_printer.print("hello world"))
    print(canon_printer.print("hello world"))
    print(epson_printer.print("hello world"))


class PrinterController:
    def __init__(self, printer):
        self.printer = printer

    def print(self, message):
        return f"Printing {message} with {type(self.printer).__name__}"


if __name__ == "__main__":
    main()
