Here is the translation of the given Java code into equivalent Python:

```Python
class WrappedKeyStroke:
    KEY_CODE = "KeyCode"
    MODIFIERS = "Modifiers"

    def __init__(self):
        pass

    def __init__(self, key_stroke: KeyStroke) -> None:
        self.key_stroke = key_stroke

    @property
    def object(self) -> object:
        return self.key_stroke

    def read_state(self, save_state: dict) -> None:
        if KEY_CODE in save_state and MODIFIERS in save_state:
            keyCode = save_state[KEY_CODE]
            modifiers = save_state[MODIFIERS]

            version = sys.version
            if version.startswith("3."):
                modifiers &= 0x0f
                modifiers |= (modifiers << 6)
            elif version.startswith("2.7") or version.startswith("2.6"):
                modifiers &= 0x0f

            self.key_stroke = KeyStroke(keyCode, modifiers)

    def write_state(self, save_state: dict) -> None:
        if self.key_stroke is not None:
            save_state[KEY_CODE] = self.key_stroke.get_key_code()
            save_state[MODIFIERS] = self.key_stroke.get_modifiers()

    @property
    def option_type(self) -> str:
        return "Keystroke Type"

    def __str__(self) -> str:
        if self.key_stroke is not None:
            return f"{self.key_stroke}"
```

Note: Python does not have direct equivalent of Java's KeyStroke class. The above code assumes that you are using a custom `KeyStroke` class in your application, and the methods used here (`get_key_code`, `get_modifiers`) should be implemented according to how this class is defined in your project.

Also note that Python has no concept of "reflection" like Java does.