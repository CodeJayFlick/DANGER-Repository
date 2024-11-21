class Goblin:
    def __init__(self):
        self.__init__("Goblin", "small", "walking", "green", 30.0)

    def __init__(self, mass: float):
        super().__init__("Goblin", "small", "walking", "green", mass)
