Here is a translation of the Java interface into equivalent Python classes:

```Python
class InterpreterConsole:
    def __init__(self):
        self.std_in = None
        self.std_out = None
        self.std_err = None
        self.out_writer = None
        self.err_writer = None
        self.prompt = ""
        self.transient = False

    def clear(self):
        pass  # No equivalent in Python, but you could implement this method to do something like clearing a console buffer.

    @property
    def std_in(self):
        return self._std_in

    @std_in.setter
    def std_in(self, value):
        self._std_in = value

    @property
    def std_out(self):
        return self._std_out

    @std_out.setter
    def std_out(self, value):
        self._std_out = value

    @property
    def std_err(self):
        return self._std_err

    @std_err.setter
    def std_err(self, value):
        self._std_err = value

    @property
    def out_writer(self):
        return self._out_writer

    @out_writer.setter
    def out_writer(self, value):
        self._out_writer = value

    @property
    def err_writer(self):
        return self._err_writer

    @err_writer.setter
    def err_writer(self, value):
        self._err_writer = value

    def set_prompt(self, prompt: str) -> None:
        self.prompt = prompt

    def is_transient(self) -> bool:
        return self.transient

    def set_transient(self, transient: bool) -> None:
        self.transient = transient

    def add_action(self, action):
        pass  # No equivalent in Python for adding a docking action.

    def add_first_activation_callback(self, callback):
        pass  # No equivalent in Python for adding an activation callback.

    def is_input_permitted(self) -> bool:
        return True  # Default to permitting input.

    def set_input_permitted(self, permitted: bool) -> None:
        if not isinstance(permitted, bool):
            raise ValueError("Input permission must be a boolean.")

    @property
    def visible(self):
        pass  # No equivalent in Python for checking visibility. You could implement this property to return the result of some method that checks whether the console is on-screen.

    def show(self) -> None:
        pass  # No equivalent in Python for showing the console's provider.

    def update_title(self) -> None:
        pass  # No equivalent in Python for updating the title.
```

This translation maintains the same interface as the original Java code, but it does not include all of the methods and properties. Some methods were removed because they do not have direct equivalents in Python or are unnecessary without additional context about how you plan to use this class.