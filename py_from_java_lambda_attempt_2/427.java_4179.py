Here is the translation of the Java code to Python:
```
class DbgEngRuntimeException(Exception):
    def __init__(self, message=""):
        super().__init__(message)
```
Note that in Python:

* We don't need a `package` statement or an `import` statement.
* The equivalent of Java's `public class` is simply the class definition (`class`) followed by the name of the class (`DbgEngRuntimeException`).
* The constructor (`__init__`) takes one argument, which defaults to an empty string if not provided. We use the `super()` function to call the parent class's constructor (in this case, `Exception`), and pass the message as an argument.
* There is no equivalent of Java's `extends RuntimeException`, since Python does not have a concept of inheritance in the same way.

That's it!