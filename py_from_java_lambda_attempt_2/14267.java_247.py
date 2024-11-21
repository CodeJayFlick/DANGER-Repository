Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import enum

class ActionType(enum.Enum):
    CONTENT_CHANGED = "CONTENT_CHANGED"

class ContentAction:
    def __init__(self, content: 'Content'):
        super().__init__()
        self.content = content

    @property
    def content(self) -> 'Content':
        return self._content

# No equivalent to Java's public access modifier in Python,
# so we'll just use the class definition as is.
class Content:
    pass
```
Note that I've used type hints for the `__init__` method and the `content` property, which are not strictly necessary but can be helpful for code readability and static analysis.