Here is the translation of the given Java code into Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from abc import ABCMeta, abstractmethod

class SerializableChecker(metaclass=ABCMeta):
    """@author Peter Güttinger"""
    
    @abstractmethod
    def __init__(self):
        pass
    
SerializableChecker = type('SerializableChecker', (), {'__module__': 'ch.njol.skript.classes'})
```

Please note that Python does not have direct equivalent of Java's `interface` keyword. Instead, we use abstract classes with abstract methods to achieve similar functionality.