class Shark:
    def __init__(self):
        self.__init__("Shark", "normal", "swimming", "light")

    def __init__(self, mass: float) -> None:
        super().__init__("Shark", "normal", "swimming", "light", mass)
