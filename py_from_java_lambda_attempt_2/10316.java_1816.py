Here is the translation of the Java code to Python:
```
class WrappedCustomOption:
    def __init__(self):
        self.value = None

    def read_state(self, save_state):
        custom_option_class_name = save_state.get("CUSTOM OPTION CLASS", None)
        try:
            value.__dict__.update(save_state)  # equivalent to value.readState(save_state)
        except Exception as e:
            print(f"Can't create customOption instance for: {custom_option_class_name}", file=sys.stderr)

    def write_state(self, save_state):
        save_state["CUSTOM OPTION CLASS"] = self.value.__class__.__name__
        self.value.write_state(save_state)  # equivalent to value.writeState(save_state)

    @property
    def object(self):
        return self.value

    @property
    def option_type(self):
        return "CUSTOM_ TYPE"  # equivalent to OptionType.CUSTOM_TYPE in Java
```
Note that I made the following changes:

* In Python, we don't need a separate `public` keyword for methods and variables.
* The constructor (`__init__`) is called when an instance of the class is created. It initializes the `value` attribute to `None`.
* The `read_state` method reads the state from a dictionary-like object (equivalent to Java's `SaveState`). If there are any issues creating the custom option, it prints an error message.
* The `write_state` method writes the state of the custom option back into the dictionary. It also calls the equivalent of `value.writeState(save_state)` on the underlying value.
* I used Python's built-in `property` decorator to create read-only properties for `object` and `option_type`. This is similar to Java's getter methods.

Keep in mind that this translation assumes you have a separate class called `CustomOption` with its own implementation.