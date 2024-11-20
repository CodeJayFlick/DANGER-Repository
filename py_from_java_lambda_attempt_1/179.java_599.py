Here is the translation of the Java code to Python:
```
class DebuggerAvailableRegistersActionContext:
    def __init__(self, selection):
        self.selection = selection

    @property
    def selection(self):
        return self._selection

    def get_selection(self):
        return self._selection


# Example usage:
if __name__ == "__main__":
    class AvailableRegisterRow:  # Note: This is not a built-in Python type, you may need to define it elsewhere in your code
        pass

    selection = [AvailableRegisterRow(), AvailableRegisterRow()]
    action_context = DebuggerAvailableRegistersActionContext(selection)
    print(action_context.selection)  # prints the selected registers
```
Note that I used Python's `class` keyword to define a class, and `def __init__` to initialize an instance of the class. The `@property` decorator is used to create a read-only property for the `selection` attribute.

Also note that in Python, we don't need to specify types for variables or method parameters like Java does with `Collection<AvailableRegisterRow>` and such. Instead, we rely on duck typing and let the code run without explicit type declarations.