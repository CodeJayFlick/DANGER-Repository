Here is the translation of the Java code to Python:

```Python
class Shark:
    def __init__(self):
        self.__init__("Shark", "normal", "swimming", "light")

    def __init__(self, mass: float) -> None:
        super().__init__("Shark", "normal", "swimming", "light", mass)
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you would typically put your classes in separate files or modules.

Also note that the copyright notice and license information are not directly translatable to Python code, but it is common practice to include such notices at the top of Python source files as well.