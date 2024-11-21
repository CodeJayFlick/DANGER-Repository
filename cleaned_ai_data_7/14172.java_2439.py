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
