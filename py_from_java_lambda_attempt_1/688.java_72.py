Here is the translation of the given Java code into Python:

```Python
class DbgBreakpointModifiedEvent:
    def __init__(self, info=None):
        self.bpt_id = None
        if info:
            super().__init__(info)
            self.bpt_id = info.get_number()
        else:
            super().__init__(None)

    @property
    def breakpoint_info(self):
        return self.info

    @property
    def id(self):
        return self.bpt_id


class DbgBreakpointInfo:  # Assuming this class exists in the original code, if not you can create it as well.
    pass
```

Please note that Python does not have direct equivalent of Java's `package`, `public` and `private`. In Python, everything is public by default. If you want to make something private or protected, you would typically use a single underscore (`_`) prefix for variables or methods which are intended to be private (but still accessible), or double underscores (`__`) for true name mangling.

Also note that the `DbgBreakpointInfo` class is not defined in this code. If it exists elsewhere in your project, you would need to import it and use its methods as needed.