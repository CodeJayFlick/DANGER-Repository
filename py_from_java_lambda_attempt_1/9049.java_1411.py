Here is the equivalent Python code:

```Python
class ErrorStatus:
    def __init__(self):
        self.exceptions = []

    def has_errors(self):
        return len(self.exceptions) > 0

    def print_message(self):
        message = "<html>"
        for exception in self.exceptions:
            message += str(exception) + "<br>"
        return message

    def print_log_message(self):
        log_message = ""
        for exception in self.exceptions:
            log_message += str(exception) + "\n"
        return log_message

    def add_exception(self, e):
        self.exceptions.append(e)

    def get_exceptions(self):
        return self.exceptions
```

Note that Python does not have direct equivalents to Java's `ArrayList` and `StringBuilder`. Instead, we use a list (`self.exceptions`) for storing exceptions and the `str()` function (or string concatenation) for building strings.