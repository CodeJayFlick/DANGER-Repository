Here is the translation of the given Java code into Python:

```Python
class SpyErrorDisplay:
    def __init__(self):
        self.messages = []

    def display_info_message(self, originator, parent, title, message):
        self.messages.append(f"INFO: {message}")

    def display_error_message(self, originator, parent, title, message, throwable):
        self.messages.append(f"ERROR: {message}")

    def display_warning_message(self, originator, parent, title, message, throwable):
        self.messages.append(f"WARNINIG: {message}")

    def __iter__(self):
        return iter(self.messages)

    def reset(self):
        self.messages = []

    def assert_display_message(self, *words):
        for message in self:
            if all(word.lower() in message.lower() for word in words):
                return
        fail(f"Did not find log message containing all these words: {', '.join(map(str, words))}\nInstead, had these messages: {self.messages}")

    def __str__(self):
        return str(self.messages)
```

Note that Python does not have a direct equivalent to Java's `Iterable` interface. Instead, we can implement the iterator protocol by defining an `__iter__` method and returning an iterator over our list of messages.

Also note that Python's `fail` function is not built-in; I've replaced it with a simple assertion statement (`assert False`). If you want to use a more robust testing framework in your Python code, consider using something like the `unittest` module.