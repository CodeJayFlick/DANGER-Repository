Here is the translation of the Java code to Python:
```
class UDTFSign:
    def __init__(self):
        pass

    def set_transformer(self):
        self.transformer = lambda x: math.copysign(1, x)
```
Note that I've used a lambda function as the transformer, which is equivalent to the `Math::signum` method in Java. The `copysign` function from the `math` module returns the sign of its second argument and the magnitude of its first argument.

Also, since Python doesn't have an exact equivalent to Java's `@Override` annotation, I've simply omitted it.