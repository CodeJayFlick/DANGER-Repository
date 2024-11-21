class Wizard:
    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return self.name


# Example usage:
wizard1 = Wizard("Gandalf")
print(wizard1)
