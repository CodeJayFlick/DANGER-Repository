Here's your Java class translated into a Python class:

```Python
class AutocompletionEvent:
    def __init__(self, sel, field):
        self.sel = sel
        self.field = field
        self.consumed = False
        self.cancelled = False

    @property
    def selection(self):
        return self.sel

    @property
    def field_(self):
        return self.field

    def consume(self):
        self.consumed = True

    @property
    def is_consumed(self):
        return self.consumed

    def cancel(self):
        self.cancelled = True

    @property
    def is_cancelled(self):
        return self.cancelled
```

Note that Python does not have direct support for generics like Java, so the type parameter `<T>` has been removed. Also, Python's `@property` decorator can be used to create getter and setter methods for attributes in a more concise way than writing separate get and set methods.