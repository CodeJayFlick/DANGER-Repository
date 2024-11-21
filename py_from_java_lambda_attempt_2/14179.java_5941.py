Here is the translation of the given Java code into Python:

```Python
class Unit:
    def __init__(self, name):
        self.name = name

    @property
    def unit_extension(self):
        return None

    @unit_extension.setter
    def set_unit_extension(self, extension_name):
        pass


# Usage example:
if __name__ == "__main__":
    my_unit = Unit("MyUnit")
    print(my_unit.name)
```

Note that Python does not have direct equivalents for Java's `@Setter` and `@Getter` annotations. Instead, we use the built-in property decorator (`@property`) to create getter and setter methods.

In this example, I've created a simple class called `Unit`. The constructor takes in a name parameter which is stored as an instance variable. There are also two properties: one for getting the unit extension (which always returns None) and another for setting it (which does nothing).