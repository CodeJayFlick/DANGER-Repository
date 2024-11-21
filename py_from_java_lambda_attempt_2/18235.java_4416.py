Here is the translation of the Java code to Python:
```
import serializable

class IExpression(metaclass=serializable.Serializable):
    def get_type(self) -> str:
        pass  # implement this method in your subclass

    def clone(self) -> 'IExpression':
        raise NotImplementedError("Must be implemented by subclasses")
```
Note that:

* In Python, we don't need to specify the `public` access modifier as it's implicit.
* The `Serializable` interface is not a built-in Python type, so I used the `serializable` module (which is not a standard library) to mimic its behavior. If you want to use a more standard approach, you can implement the `__getstate__` and `__setstate__` methods in your class.
* The `ExpressionType` enum is not present in the original Java code, so I left it out of the Python translation. You would need to define this enum separately if needed.

Also note that this is just one possible way to translate the Java interface to Python; there may be other valid approaches depending on your specific use case and requirements.