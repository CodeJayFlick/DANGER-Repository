class StringChoices:
    def __init__(self, values):
        if not values or len(values) == 0:
            raise ValueError("Set of values must contain at least one value")
        self.values = list(values)
        self.selected = 0

    def get_values(self):
        return self.values[:]

    def get_selected_value(self):
        return self.values[self.selected]

    def get_selected_value_index(self):
        return self.selected

    def contains(self, value):
        try:
            index = self.values.index(value)
            return True
        except ValueError:
            return False

    def index_of(self, value):
        for i in range(len(self.values)):
            if self.values[i] == value:
                return i
        return -1

    def set_selected_value(self, value):
        try:
            index = self.values.index(value)
            self.selected = index
        except ValueError:
            raise ValueError("No such value in Enum")

    def set_selected_value_index(self, index):
        if 0 <= index < len(self.values):
            self.selected = index
        else:
            raise ValueError("index out of range")

    def __hash__(self):
        return hash((self.selected, tuple(self.values)))

    def __eq__(self, other):
        if not isinstance(other, StringChoices):
            return False
        if self.selected != other.selected or self.values != other.values:
            return False
        return True

    def __str__(self):
        return str(self.get_selected_value())
