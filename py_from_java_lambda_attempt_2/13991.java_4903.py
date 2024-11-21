Here is the translation of the given Java code into equivalent Python:

```Python
import logging

class RenderComponent:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def update(self):
        pass  # do nothing

    def render(self):
        self.logger.info("Render Component")
```

Note that in this translation, I have used the built-in Python `logging` module to implement a simple logger. The equivalent of Java's `Slf4j` is not directly available in Python, so we use the standard logging module instead.

Also note that there are no direct equivalents for Java concepts like packages (`package com.iluwatar.data.locality.game.component;`) or annotations (like `@Slf4j`). In Python, these things do not exist at all.