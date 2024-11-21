class Dragon:
    def __init__(self):
        self.__init__("Dragon", "LARGE", "FLYING", "RED", 39300.0)

    def __init__(self, mass: float):
        super().__init__("Dragon", "LARGE", "FLYING", "RED", mass)
