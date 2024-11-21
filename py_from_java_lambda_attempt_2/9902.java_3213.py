Here is the translation of the Java code to Python:
```
import threading

class DefaultGTreeDataTransformer:
    def __init__(self):
        self.localized_results = threading.local()

    def transform(self, node):
        results = getattr(self.localized_results, 'results', None)
        if not results:
            results = []
            setattr(self.localized_results, 'results', results)

        results.clear()
        results.append(node.display_text())
        return results
```
Note that I used the `threading.local()` class to implement a thread-local variable in Python. This is equivalent to Java's `ThreadLocal` class.

Also, I replaced the `List<String>` with a simple list of strings (`[]`) and removed the explicit type declarations for variables and function parameters, as they are not necessary in Python.