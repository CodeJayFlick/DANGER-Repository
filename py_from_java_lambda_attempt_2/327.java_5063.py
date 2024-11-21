Here is the translation of the Java interface into a Python class:

```Python
class LogicalBreakpointsChangeListener:
    def breakpoint_added(self, added):
        pass

    def breakpoints_added(self, added):
        for a in added:
            self.breakpoint_added(a)

    def breakpoint_updated(self, updated):
        pass

    def breakpoints_updated(self, updated):
        for u in updated:
            self.breakpoint_updated(u)

    def breakpoint_removed(self, removed):
        pass

    def breakpoints_removed(self, removed):
        for r in removed:
            self.breakpoint_removed(r)

    def location_added(self, added):
        pass

    def location_updated(self, updated):
        pass

    def location_removed(self, removed):
        pass
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, we define a class with methods that are meant to be overridden by subclasses or used as is for simple cases where the default implementation provided here suffices.