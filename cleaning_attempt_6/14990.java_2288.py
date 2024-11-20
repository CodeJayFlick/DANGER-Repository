class KillerBee:
    def __init__(self):
        self.__init__("KillerBee", "small", "flying", "light")

    def __init__(self, mass: Mass) -> None:
        super().__init__("KillerBee", "small", "flying", "light", mass)

class AbstractCreature:
    def __init__(self, name: str, size: str, movement: str, color: str, mass: 'Mass') -> None:
        pass

class Mass:
    def __init__(self, value):
        self.value = value
