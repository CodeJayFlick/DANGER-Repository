Here is the translation of the Java code to Python:

```Python
class KillerBee:
    def __init__(self):
        self.__init__("KillerBee", "small", "flying", "light")

    def __init__(self, mass: Mass) -> None:
        super().__init__("KillerBee", "small", "flying", "light", mass)

class AbstractCreature:
    def __init__(self, name: str, size: str, movement: str, color: str, mass: 'Mass') -> None:
        pass

class Mass:
    def __init__(self, value):
        self.value = value
```

Please note that Python does not have direct equivalent of Java's `package`, so I did not include any package declaration. Also, the concept of classes and objects in Python is similar to Java but there are some differences like private variables (Python uses double underscore prefix), static methods (Python uses classmethod decorator) etc.

Also, note that this code does not actually define what "small", "flying" or "light" mean - these would need to be defined elsewhere.