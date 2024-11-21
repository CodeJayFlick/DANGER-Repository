Here's your Java code translated into Python:

```Python
import logging

class AngryState:
    def __init__(self, mammoth):
        self.mammoth = mammoth

    def observe(self):
        logging.info("{} is furious!".format(self.mammoth))

    def on_enter_state(self):
        logging.info("{} gets angry!".format(self.mammoth))
```

Note that Python does not have a direct equivalent to Java's `@Slf4j` annotation. Instead, we're using the built-in `logging` module in this example.