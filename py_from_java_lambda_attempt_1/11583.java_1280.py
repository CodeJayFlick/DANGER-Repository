Here is the translation of the Java code to Python:
```
class UnsupportedFloatFormatException(Exception):
    def __init__(self, message="Unsupported float format"):
        super().__init__(message)

def main():
    try:
        # example usage
        raise UnsupportedFloatFormatException(42)
    except UnsupportedFloatFormatException as e:
        print(e)

if __name__ == "__main__":
    main()
```
Note that I've removed the `package` declaration, as Python doesn't have a concept of packages like Java does. Instead, we define a class `UnsupportedFloatFormatException` that inherits from the built-in `Exception` class.

The constructor (`__init__`) takes an optional argument `message`, which is used to set the error message when raising the exception. If no message is provided, it defaults to "Unsupported float format".

In the example usage, we raise an instance of this exception with a specific message using the `raise` statement. We then catch and print the exception in the `main()` function.

Finally, I've added a simple `if __name__ == "__main__": main()` block at the end to ensure that the `main()` function is only executed when the script is run directly (i.e., not imported as a module).