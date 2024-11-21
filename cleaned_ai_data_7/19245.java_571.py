class IsCharged:
    def __init__(self):
        self.description = "Checks if a creeper is charged (powered)."
        self.name = "Is Charged"

    @property
    def description(self):
        return self.__description

    @description.setter
    def description(self, value):
        self.__description = value

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    def __call__(self, e):
        if isinstance(e, Creeper):
            return e.is_powered()
        else:
            return False


def register(cls):
    pass  # This is equivalent to the Java static block. In Python, we don't have direct equivalents of Java's static blocks.


# Usage example
is_charged = IsCharged()

creeper = Creeper()  # Assuming you have a Creeper class in your code.
if is_charged(creeper):
    print("The creeper is charged.")
else:
    print("The creeper is not charged.")

