Here is the translation of the given Java code into equivalent Python:

```Python
class Filterer(G, E):
    def __init__(self, predicate: callable) -> None:
        self.predicate = predicate

    def by(self) -> G:
        return self.predicate
```

Please note that this is a direct translation and might not be exactly what you would expect from the Java code. Python does not have built-in support for functional interfaces like `@FunctionalInterface` in Java, nor does it have type parameters `<G>` or `<E>`.