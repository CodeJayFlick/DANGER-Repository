Here is the translation of the given Java interface into a Python equivalent:

```Python
import io.Serializable

class ExpressionValue(Serializable):
    def long_value(self, buf: bytes, offset: int) -> int:
        pass  # implement this method in your subclass

    def length(self, buf: bytes, offset: int) -> int:
        pass  # implement this method in your subclass
```

Note that Python does not have direct equivalent of Java's interface. Instead, we can use abstract base classes (ABCs) to achieve similar functionality. In the above code, `ExpressionValue` is an ABC which has two methods: `long_value` and `length`. These methods are declared as abstract because they do not have any implementation in this class.