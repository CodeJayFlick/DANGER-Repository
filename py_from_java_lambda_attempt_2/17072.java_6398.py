Here is the translation of the Java code to Python:
```
class DistanceMetricException(Exception):
    def __init__(self, message):
        super().__init__(message)

serialVersionUID = -2772568110478978387
```
Note that I've kept the `serialVersionUID` as a constant in Python, since it's not possible to have static final variables like Java. Also, I've used the built-in `Exception` class from Python and overridden its constructor with our own implementation.

In Python, we don't need explicit getters or setters for attributes, so I didn't include those either.