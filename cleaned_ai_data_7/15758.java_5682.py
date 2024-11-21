class Pair:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    @property
    def key(self):
        return self.key

    @property
    def value(self):
        return self.value

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, Pair) or type(self) != type(other):
            return False
        else:
            return self.key == other.key and self.value == other.value

    def __hash__(self):
        return hash((self.key, self.value))
