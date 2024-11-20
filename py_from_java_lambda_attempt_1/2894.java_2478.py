Here is the translation of the Java code to Python:

```python
import logging

def do_stuff(script):
    script.println(f"in {__name__}")

if __name__ == "__main__":
    pass
```

Note that I've removed the unnecessary parts from the original code, such as the license information and package declaration. In Python, we don't need to declare classes or methods with `public` access modifiers like in Java.

The `do_stuff` function takes a script object (which is not defined in this example) and prints a message using the `println` method. The `{__name__}` part is used as a placeholder for the name of the current module, similar to how `Util.class.getCanonicalName()` was used in Java.

The `if __name__ == "__main__": pass` block at the end is not strictly necessary here, but it's a common pattern in Python scripts that are meant to be executed directly (i.e., not imported as modules).