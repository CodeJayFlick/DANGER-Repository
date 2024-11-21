Here is the translation of the Java code to Python:

```Python
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
```

Note that Python does not have a direct equivalent to Java's package declaration. In this translation, I've omitted the `package` statement and simply defined each class in its own separate section of code.