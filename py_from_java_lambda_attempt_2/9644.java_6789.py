Here is the translation of the Java enum code to Python:

```
class MultitermEvaluationMode:
    AND = ("Object must match all filter terms",)
    OR = ("Object must match at least one filter term",)

    def __init__(self, descr):
        self.descr = descr

    @property
    def description(self):
        return self.descr
```

Note that in Python, we don't need to use an `enum` class like Java does. Instead, we can define a regular class with static attributes and methods. The `@property` decorator is used to create a read-only property for the `description`.