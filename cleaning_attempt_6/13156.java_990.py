class CheckCastTest:
    def object_cast(self, x):
        if isinstance(x, int):
            return x
        else:
            try:
                y = int(x)
                return y
            except TypeError:
                return None

    def interface_cast(self, x):
        if hasattr(x, '__gt__'):
            return x
        else:
            try:
                y = Comparable(x)
                return y
            except AttributeError:
                return None

    def primitive_array_cast(self, x):
        if isinstance(x, list) and all(isinstance(i, int) for i in x):
            return x
        elif hasattr(x, '__getitem__'):
            try:
                array = [int(i) for i in x]
                return array
            except TypeError:
                return None

    def object_array_cast(self, x):
        if isinstance(x, list) and all(isinstance(i, int) for i in x):
            return x
        elif hasattr(x, '__getitem__'):
            try:
                array = [int(i) for i in x]
                return array
            except TypeError:
                return None

class Comparable:
    def __init__(self, value):
        self.value = value

    def __gt__(self, other):
        if isinstance(other, int):
            return self.value > other
        else:
            raise AttributeError("Can only compare with integers")
