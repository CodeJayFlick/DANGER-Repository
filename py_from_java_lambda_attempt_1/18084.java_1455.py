Here is the translation of the Java code to Python:
```
class QueryOperatorException(Exception):
    def __init__(self, message):
        super().__init__(message)

serialVersionUID = 8581594261924961899
```
Note that:

* In Python, we don't need a `package` statement or an explicit class declaration. We simply define the class using the `class` keyword.
* The `extends LogicalOptimizeException` part is not necessary in Python, as classes are not inherited by default (you would use multiple inheritance to achieve similar behavior).
* The `private static final long serialVersionUID = 8581594261924961899L;` line can be removed entirely, as it's specific to Java serialization and has no equivalent concept in Python.
* In the constructor (`__init__` method), we simply call the parent class's constructor using `super().__init__(message)`, which is similar to calling a superclass constructor in Java.

That's it!