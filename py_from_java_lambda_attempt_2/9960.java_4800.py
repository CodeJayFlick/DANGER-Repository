Here is the translation of the Java code to Python:
```
class SettingsDefinition:
    @staticmethod
    def concat(settings: list, *additional) -> list:
        if additional == []:
            return settings
        if settings == []:
            return [s for s in additional]
        
        result = settings + list(additional)
        return result

    def has_value(self, setting):
        pass  # Not implemented in Java either!

    @property
    def name(self) -> str:
        raise NotImplementedError("Name not implemented")

    @property
    def description(self) -> str:
        raise NotImplementedError("Description not implemented")

    def clear(self, settings: dict):
        for key in list(settings.keys()):
            if self.name() == key:
                del settings[key]

    def copy_setting(self, src_settings: dict, dest_settings: dict):
        for key, value in src_settings.items():
            if self.name() == key:
                dest_settings[key] = value
```
Note that I've made the following changes:

* In Python, we don't need to declare types explicitly like Java does. Instead, we use type hints (e.g., `-> str`) which are optional.
* The `SettingsDefinition` class is now a regular Python class with methods and properties instead of an interface in Java.
* I've removed the `public` access modifier since it's not necessary in Python.
* In the `concat` method, I used list concatenation (`+`) to combine the two lists. This is equivalent to the Java code that uses `System.arraycopy`.
* The other methods are mostly identical to their Java counterparts, with some minor changes due to differences between languages (e.g., using `@property` for getters and setters instead of separate getter/setter methods).

Keep in mind that this translation assumes you're working with Python 3.x. If you need help with an earlier version or have specific questions about the code, feel free to ask!