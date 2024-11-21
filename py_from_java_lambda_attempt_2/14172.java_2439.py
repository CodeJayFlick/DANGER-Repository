Here is the translation of the given Java code into Python:

```Python
import logging

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def main(self, args=None):
        soldier_unit = SoldierUnit("SoldierUnit1")
        sergeant_unit = SergeantUnit("SergeantUnit1")
        commander_unit = CommanderUnit("CommanderUnit1")

        check_extensions_for_unit(soldier_unit)
        check_extensions_for_unit(sergeant_unit)
        check_extensions_for_unit(commander_unit)

    def check_extensions_for_unit(self, unit):
        name = unit.get_name()
        extension_func_map = {
            "SoldierExtension": lambda: self.logger.info(f"{name} without SoldierExtension"),
            "SergeantExtension": lambda: self.logger.info(f"{name} without SergeantExtension"),
            "CommanderExtension": lambda: self.logger.info(f"{name} without CommanderExtension")
        }

        for extension in ["SoldierExtension", "SergeantExtension", "CommanderExtension"]:
            unit_extension = getattr(unit, f"get_{extension}_extension")()
            if unit_extension:
                func = extension_func_map[extension]
                func()

class SoldierUnit:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


class SergeantUnit(SoldierUnit):
    pass


class CommanderUnit(SergeantUnit):
    pass
```

Please note that Python does not have direct equivalent of Java's Optional class. The code uses a dictionary to map extensions to functions for simplicity, but you might want to consider using the `functools.partial` function or creating your own optional-like structure if you need more complex logic.

Also, this translation assumes that there are classes like SoldierUnit, SergeantUnit and CommanderUnit with methods get_name() and get_unit_extension(). You would have to implement these classes in Python as well.