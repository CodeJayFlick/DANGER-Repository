Here is the translation of the given Java code into Python:

```Python
class StringEventsTask:
    def __init__(self, string_model, options, events):
        self.string_model = string_model
        self.options = options
        self.events = events

    def run(self):
        for event in self.events:
            event.process(self.string_model, self.options)
```

Note that Python does not have direct equivalents of Java's `Task` and `List`, so I've replaced them with simple attributes. Also, the equivalent of Java's constructor is a special method named `__init__`.