Here is the translation of the Java code to Python:

```Python
import logging

class Mammoth:
    pass


class PeacefulState:
    def __init__(self, mammoth):
        self.mammoth = mammoth

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def observe(self):
        self.logger.info("{} is calm and peaceful.".format(self.mammoth))

    def on_enter_state(self):
        self.logger.info("{} calms down.".format(self.mammoth))
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. In this translation, I've used the built-in logging module to achieve similar functionality.