Here is the translation of the Java code to Python:
```
class MissingFileInvalidLink(Exception):
    def __init__(self, href):
        super().__init__("Unable to locate reference file")
        self.href = href
```
Note that I've translated `public class` to just `class`, as this is not a reserved keyword in Python. Additionally, the Java concept of an "exception" (i.e., an error condition) is equivalent to raising an exception in Python.

In particular, I've defined a custom exception class `MissingFileInvalidLink` that inherits from the built-in `Exception` class. The constructor takes one argument (`href`) and sets it as an instance variable. When raised, this exception will print the message "Unable to locate reference file" followed by any additional information provided in the constructor call.

If you want to create a separate Python module for this code (equivalent to Java's `package` statement), you can do so using the following syntax:
```
# missing_file_invalid_link.py
class MissingFileInvalidLink(Exception):
    def __init__(self, href):
        super().__init__("Unable to locate reference file")
        self.href = href

if __name__ == "__main__":
    pass  # This code is not intended to be run directly; it's a module.
```
This defines the `MissingFileInvalidLink` class in its own Python module.