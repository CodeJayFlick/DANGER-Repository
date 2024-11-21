Here is the translation of the given Java code into Python:

```Python
class DbgEnableBreakpointsCommand:
    def __init__(self, manager, *numbers):
        self.manager = manager
        self.numbers = numbers

    def invoke(self):
        control = self.manager.get_control()
        for num in self.numbers:
            bp = control.get_breakpoint_by_id(int(num))
            bp.add_flags("ENABLED")
```

Note that Python does not have direct equivalents of Java's `package`, `import` statements, or the concept of classes and methods. The above code is a straightforward translation into Python syntax.