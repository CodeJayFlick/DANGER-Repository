Here is the translation of the Java code to Python:
```
import concurrent.futures

class Evaluator:
    def evaluate(self, window: 'Window') -> None:
        raise Exception()

    def on_rejection(self, window: 'Window') -> None:
        raise concurrent.futuresRejectedExecutionException()
```
Note that I used type hints for the `evaluate` and `on_rejection` methods to indicate their parameters. In Python 3.5+, you can use the `->` syntax to specify the return type of a function.

Also, I replaced the Java-specific annotations (`@FunctionalInterface`, `@SuppressWarnings`) with equivalent Python constructs (e.g., using a class instead of an interface).

The rest of the code is straightforward: we define two methods on the `Evaluator` class. The first method takes a `Window` object as input and raises an exception. The second method also takes a `Window` object as input, but this time it raises a `RejectedExecutionException`.