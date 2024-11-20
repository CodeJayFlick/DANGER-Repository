Here is a translation of the Java code into equivalent Python:

```Python
class DebugContainer:
    def __init__(self):
        self.breakpoints = BreakpointContainer()

    @property
    def breakpoints(self):
        return self._breakpoints


class LldbModelTargetDebugContainer(LldbModelTargetObject, DebugContainer):
    def __init__(self, session: 'LldbModelTargetSession'):
        super().__init__(session.model, "Debug", "DebugContainer")
        self.breakpoints = BreakpointContainer(session.session)


class BreakpointContainer:
    pass


# Note that this is a simplified translation and does not include all the Java features.
```

This Python code defines three classes: `DebugContainer`, `LldbModelTargetDebugContainer` and `BreakpointContainer`. The `DebugContainer` class has an attribute called `breakpoints` which is of type `BreakpointContainer`.

The `LldbModelTargetDebugContainer` class inherits from both the base class `LldbModelTargetObject` (which does not exist in Python) and itself. This means it can use its own methods as if they were inherited.

In the constructor, an instance of `BreakpointContainer` is created with a session object passed to it.