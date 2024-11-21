Here is the translation of the Java code to Python:
```
import math

class UDTFSin:
    def set_transformer(self):
        self.transformer = lambda x: math.sin(x)
```
Note that in Python, we don't need an `@Override` annotation because method overriding works differently than in Java. Also, the `transformer` attribute is assigned a lambda function instead of being set to a static method like in Java.

Also, I removed the license information and package declaration as they are not relevant to the translation itself.