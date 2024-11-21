Here is the translation of the Java code to Python:
```
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class SimpleNode:
    def __init__(self, value: str, comment: str, line_num: int, parent=None):
        super().__init__(value, comment, parent, line_num)

    @classmethod
    def from_config(cls, c):
        return cls(c)

    def save_i(self) -> str:
        # Suppress null warning for Python 3.6 and earlier
        if self.key is not None:
            return self.key

    def set(self, s: str):
        self.key = s

# Copyright Peter Güttinger, SkriptLang team and contributors
```
Note that I've removed the Java-specific comments (e.g., `@author`) as they are not necessary in Python. Additionally, I've used type hints for the method parameters and return types to provide a hint about the expected data types.