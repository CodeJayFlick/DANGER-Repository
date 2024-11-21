Here is the translation of the given Java code into Python:

```Python
class AbstractAssemblyProduction:
    def __init__(self, lhs: 'AbstractAssemblyNonTerminal', rhs):
        self.lhs = lhs
        self.rhs = rhs
        self.idx = -1  # Initialize index to -1

    @property
    def idx(self):
        return self._idx

    @idx.setter
    def idx(self, value):
        if not isinstance(value, int):
            raise TypeError("Index must be an integer")
        self._idx = value

    def __str__(self):
        return f"{self.idx}. {self.lhs} => {self.rhs}"

    def __eq__(self, other):
        if not isinstance(other, AbstractAssemblyProduction):
            return False
        if self.lhs != other.lhs:
            return False
        if self.rhs != other.rhs:
            return False
        return True

    def __lt__(self, other):
        if self.lhs < other.lhs:
            return True
        elif self.lhs == other.lhs:
            return self.rhs < other.rhs
        else:
            return False

    def __hash__(self):
        return hash((self.lhs.__hash__(), self.rhs.__hash__()))

class AssemblySentential:
    pass  # This class is not implemented in the given Java code, so it's left as a placeholder.

class AbstractAssemblyNonTerminal:
    @property
    def name(self):
        raise NotImplementedError("Subclasses must implement this method")

# Example usage:

class MyAssemblyNonTerminal(AbstractAssemblyNonTerminal):
    def __init__(self, name: str):
        self.name = name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value


# Create an instance of the production class:
production1 = AbstractAssemblyProduction(MyAssemblyNonTerminal('lhs'), ['symbol1', 'symbol2'])
print(production1)  # Output: -1. lhs => ['symbol1', 'symbol2']

# Set the index for this production:
production1.idx = 0
print(production1)  # Output: 0. lhs => ['symbol1', 'symbol2']
```

Please note that I've made some assumptions about the `AssemblySentential` class and its methods, as they were not provided in the given Java code. Also, the `AbstractAssemblyNonTerminal` class is a placeholder for now, but it should be implemented according to your specific requirements.