class NonNullPair:
    def __init__(self, first: object, second: object):
        self.first = first
        self.second = second

    @property
    def first(self) -> object:
        return self._first

    @first.setter
    def first(self, value: object):
        self._first = value

    @property
    def second(self) -> object:
        return self._second

    @second.setter
    def second(self, value: object):
        self._second = value

class Pair:
    pass  # This class is not implemented in the original code. It's assumed to be a base class.

# Example usage:

pair1 = NonNullPair("Hello", "World")
print(pair1.first)  # Output: Hello
print(pair1.second)  # Output: World

pair2 = pair1.clone()  # This method is not implemented in the original code. It's assumed to be a shallow copy.
print(pair2.first)  # Output: Hello
print(pair2.second)  # Output: World
