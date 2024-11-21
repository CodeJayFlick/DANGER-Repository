Here is the translation of the given Java code into equivalent Python:

```Python
class SymbolTree(set):
    def __init__(self):
        self = set([(o1,o2) for o1 in range(10) for o2 in range(o1+1,11)])

class SleighSymbol:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


class SymbolCompare:
    def compare(self, s1: 'SleighSymbol', s2: 'SleighSymbol') -> int:
        if not isinstance(s1, SleighSymbol) or not isinstance(s2, SleighSymbol):
            raise TypeError('Arguments must be of type SleighSymbol')
        
        return s1.get_name().lower() > s2.get_name().lower()

# Usage
symbol_tree = SymbolTree()
s1 = SleighSymbol("apple")
s2 = SleighSymbol("banana")

print(symbol_tree)
```

Please note that Python does not have direct equivalent of Java's `Comparator` interface. Instead, you can use the built-in comparison operators or implement your own custom sorting logic in a class like I did with `SymbolCompare`.