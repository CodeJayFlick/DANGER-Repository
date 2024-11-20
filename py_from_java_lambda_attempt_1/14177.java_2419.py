Here is the translation of the given Java code into equivalent Python:

```Python
class SergeantUnit:
    def __init__(self, name):
        super().__init__(name)

    def get_unit_extension(self, extension_name: str) -> Optional['Sergeant']:
        if extension_name == "SergeantExtension":
            return self.unit_extension or (lambda: new_sergeant(self))()
        else:
            return super().get_unit_extension(extension_name)


class SergeantUnit(Unit):
    pass


from abc import ABC, abstractmethod

class Unit(ABC):
    @abstractmethod
    def get_unit_extension(self, extension_name) -> Optional['Sergeant']:
        pass


from typing import Optional

def new_sergeant(unit: 'SergeantUnit') -> 'Sergeant':
    return Sergeant(unit)
```

Please note that Python does not have direct equivalent of Java's `package`, `public class`, etc. statements, so the code above is a translation into pure Python syntax and structure.