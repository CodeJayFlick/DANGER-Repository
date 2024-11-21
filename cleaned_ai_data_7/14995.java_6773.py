class Mass:
    def __init__(self, value):
        self.value = value
        self.title = f"{value:.2f} kg"

    def greater_than(self, other):
        return self.value > other.value

    def smaller_than(self, other):
        return self.value < other.value

    def greater_than_or_eq(self, other):
        return self.value >= other.value

    def smaller_than_or_eq(self, other):
        return self.value <= other.value

    def __str__(self):
        return self.title
