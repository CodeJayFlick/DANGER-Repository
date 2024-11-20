Here is the translation of the Java code into Python:

```Python
class ProgressBar:
    TOTAL_BAR_LENGTH = 40

    def __init__(self):
        self.max = 1
        self.message = ''
        self.trailing_message = ''

    def reset(self, message: str, max_value: int, trailing_message: str = None) -> None:
        if not isinstance(message, str):
            raise TypeError("Message must be a string")
        if not isinstance(max_value, int):
            raise TypeError("Max value must be an integer")

        self.message = message
        self.max = max_value
        self.trailing_message = trailing_message or ''
        self.current_percent = 0
        self.progress = 0

    def start(self, initial_progress: int) -> None:
        self.update(initial_progress)

    def end(self) -> None:
        self.update(self.max - 1)

    def increment(self, progress_increment: int) -> None:
        self.update(self.progress + progress_increment)

    def update(self, new_progress: int = None, additional_message: str = None) -> None:
        if not isinstance(new_progress, (int, type(None))):
            raise TypeError("Progress must be an integer or None")
        if not isinstance(additional_message, (str, type(None))):
            raise TypeError("Additional message must be a string or None")

        new_progress = self.progress + progress_increment
        current_percent = int((new_progress / self.max) * 100)

        if additional_message is None:
            additional_message = self.trailing_message

        print(f'\r{self.message}: {current_percent}% |{"#" * (int(new_progress / self.max * self.TOTAL_BAR_LENGTH))}{" "*(40-int(new_progress/self.max*self.TOTAL_BAR_LENGTH))}| {"  " if current_percent < 100 else ""}{additional_message}', end='')
        if new_progress >= self.max:
            print()
```

Please note that Python does not have a direct equivalent to Java's `@Override` annotation.