Here is the translation of the Java code to Python:

```Python
class LogEntry:
    def __init__(self, level: int, quality: int = 0, message: str = '', node=None):
        self.level = level
        self.quality = quality
        self.message = message
        self.node = node

    @property
    def from_(self) -> str:
        if not hasattr(self, '_from'):
            tracked = Skript.debug()
            try:
                raise Exception()
            except Exception as e:
                stack_info = ''.join(traceback.format_list(stacktrace.extract_stack(e)))
                self._from = f' (from {stack_info})'
        return getattr(self, '_from', '')

    @property
    def get_level(self) -> int:
        return self.level

    @property
    def get_quality(self) -> int:
        return self.quality

    def __str__(self):
        if not self.node or self.level < 30:  # WARNING level is 30
            return self.message
        c = self.node.config
        return f'{self.message}{self.from_} ({c.filename}, line {self.node.line}: {self.node.save().strip()})'

    def discarded(self, info):
        if not hasattr(self, 'used'):
            self.used = True
            if Skript.debug():
                logging.warning(f' # LogEntry "{self.message}"{self.from_} discarded; {info}')

    def logged(self):
        if not hasattr(self, 'used'):
            self.used = True
            if Skript.debug():
                logging.warning(f' # LogEntry "{self.message}"{self.from_} logged')

    def __del__(self):
        assert getattr(self, 'used', False), f'{self.message}{self.from_}'
```

Note: Python does not have direct equivalent of Java's `@Nullable` annotation. In this translation, I used the fact that if a variable is not set in an object, it will be considered as None by default.

Also note that Python has different way to handle exceptions and stack trace compared to Java.