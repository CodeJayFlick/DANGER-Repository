Here is the translation of the given Java code into Python:

```Python
class ProgramSelectionPluginEvent:
    NAME = "ProgramSelection"

    def __init__(self, src, selection, program):
        self.selection = selection
        self.program_ref = weakref.ref(program)

    @property
    def selection(self):
        return self._selection

    @selection.setter
    def selection(self, value):
        if value is None:
            raise ValueError("ProgramSelection cannot be null")
        self._selection = value

    @property
    def program(self):
        return self.program_ref()

class PluginEvent:
    pass


def main():
    # Example usage of the ProgramSelectionPluginEvent class.
    selection_event = ProgramSelectionPluginEvent("src", "some_selection", some_program)
    print(selection_event.selection)  # prints: some_selection
    print(selection_event.program)   # prints: some_program

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `WeakReference` class. The closest thing to it is the `weakref.ref()` function which returns a weak reference to an object, but this can be used only with objects that are instances of classes that support weak references (like lists or dictionaries).