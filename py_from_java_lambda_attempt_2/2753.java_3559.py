Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractLongOffsetPcodeExecutorState:
    def __init__(self, language: str, arithmetic):
        pass  # No direct equivalent in Python for constructor with abstract class

# Note that this is an abstract class and does not have a concrete implementation.
```

Here are some key differences between the Java code and its Python translation:

1. **Class Definition**: In Java, we define classes using `public` or `private`, but in Python, there's no need for explicit access modifiers.

2. **Constructor**: The constructor in Java is defined with a specific signature (i.e., it has parameters), whereas in Python, the equivalent method (`__init__`) can be called without any arguments if you don't want to pass anything when creating an instance of this class.

3. **Type Parameters**: In Java, we use type parameters `<T>` and `<S>` for generics, but these are not directly translatable into Python. However, in Python, you could achieve similar functionality using abstract classes or interfaces with methods that take any kind of argument (e.g., `def do_something(self, arg):`).

4. **Interface Implementation**: In Java, we implement an interface by extending it (`implements PcodeExecutorState<T>`), but this is not necessary in Python because you can use inheritance to create a new class from another one without explicitly implementing any interfaces.

5. **Abstract Methods**: Since `PcodeArithmetic` and other classes are abstract in the original Java code, there's no direct equivalent method in Python that would require an implementation (like `abstract methods`).