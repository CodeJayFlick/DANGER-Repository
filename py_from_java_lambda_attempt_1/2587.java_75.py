Here is the translation of the given Java interface into a Python class:

```Python
class TraceLabelSymbolView:
    def add(self, lifespan: range, thread: str, address: int, name: str, parent: str, source: str) -> dict:
        return {"symbol": f"Trace Label Symbol {name}", "lifespan": lifespan, "thread": thread, "address": address}

    def create(self, snap: int, thread: str, address: int, name: str, parent: str, source: str) -> dict:
        return self.add(range(snap), thread, address, name, parent, source)
```

Note that Python does not have direct equivalents for Java's interfaces or classes. Instead, we can use abstract base classes (ABCs) to define the interface and then create concrete implementations of this ABC.

Also note that in Python, there is no equivalent to Java's `throws` keyword which specifies exceptions a method may throw.