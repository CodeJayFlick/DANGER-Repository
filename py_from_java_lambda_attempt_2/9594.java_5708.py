Here is the translation of the Java code to Python:
```
class BackgroundColorModel:
    def get_background_color(self, index: int) -> tuple:
        # Note: BigInteger in Java corresponds to int in Python
        return (0, 0, 0, 255)  # Replace with actual implementation

    def get_default_background_color(self) -> tuple:
        return self.get_background_color(0)

    def set_default_background_color(self, color: tuple):
        pass  # Replace with actual implementation
```
Note that:

* In Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class and use the convention of prefixing method names with an underscore (e.g., `_get_background_color`) to indicate they are intended for internal use only.
* The `BigInteger` type in Java is not directly translatable to Python, as it is a specific implementation detail. In this translation, I've replaced it with an integer (`int`) since the context suggests that the index is likely to be a small positive integer.
* The `Color` class in Java has no direct equivalent in Python. Instead, we use tuples of four values (red, green, blue, and alpha) to represent colors.

This translation assumes you want to implement the same interface as the original Java code. If your requirements are different or if you need further modifications, please let me know!