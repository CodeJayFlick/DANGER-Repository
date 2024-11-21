Here is a translation of the Java code into equivalent Python:

```Python
class LldbDisableBreakpointsCommand:
    def __init__(self, manager, *ids):
        self.manager = manager
        self.ids = ids

    def complete(self, pending=None):
        current_session = self.manager.get_current_session()
        for id in self.ids:
            self.manager.do_breakpoint_disabled(current_session, id, pending)
        return None

    def invoke(self):
        known_breakpoints = self.manager.get_known_breakpoints(self.manager.get_current_session())
        for id in self.ids:
            if id in known_breakpoints:
                obj = known_breakpoints[id]
                if isinstance(obj, dict) and 'enabled' in obj:
                    obj['enabled'] = False
```

Note that this translation is not a direct conversion from Java to Python. Instead, it's an equivalent implementation of the same functionality using Python syntax and semantics.

Here are some key differences:

* In Python, we don't need explicit type declarations or `new` operators.
* We use dictionaries (`dict`) instead of maps (Java) for storing known breakpoints.
* We use boolean values directly to represent enabled/disabled states, rather than having separate classes like SBBreakpoint and SBWatchpoint in Java.