Here is the translation of the Java code to Python:
```python
import jna.platform.win32.WinDef as WinDef

class DbgToggleContinuationCommand:
    def __init__(self, manager: 'DbgManagerImpl', index: int, option_cont: 'DebugFilterContinuationOption'):
        self.manager = manager
        self.index = index
        self.option_cont = option_cont

    def invoke(self):
        control = self.manager.get_control()
        info = control.get_number_event_filters()
        n_events = info.number_events
        n_excs = info.number_specific_exceptions

        if self.index < n_events:
            exc = control.get_specific_filter_parameters(0, n_events)
            p = exc[self.index]
            p.continue_option = WinDef.ULONG(option_cont.ordinal())
            control.set_specific_filter_parameters(0, n_events, exc)
        else:
            exc = control.get_exception_filter_parameters(n_excs, None, 0)
            p = exc[self.index - n_events]
            p.continue_option = WinDef.ULONG(option_cont.ordinal())
            control.set_exception_filter_parameters(n_excs, exc)

class DbgManagerImpl:  # assume this class exists in the same module
    pass

class DebugFilterContinuationOption:
    def __init__(self):
        self.ordinal = None  # assume ordinal is a property of this class

# usage example:
manager = DbgManagerImpl()
option_cont = DebugFilterContinuationOption()
command = DbgToggleContinuationCommand(manager, index=1, option_cont=option_cont)
command.invoke()
```
Note that I had to make some assumptions about the classes and methods used in the original Java code. Specifically:

* `DbgManagerImpl` is assumed to be a class with a method `get_control()` that returns an instance of `DebugControl`.
* `DebugFilterContinuationOption` has an `ordinal` property, which I assume is an integer value.
* The JNA library (`jna`) and its dependencies are not explicitly imported in the original Java code. In Python, we can use a similar approach by importing the `WinDef` class from the `jna.platform.win32` module.

Please adjust these assumptions according to your specific requirements or provide more context about the classes and methods used in the original Java code.