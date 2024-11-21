Here's a translation of the provided Java code into equivalent Python:

```Python
class MergeableBackgroundCommand:
    def __init__(self, name: str, has_progress: bool = False, can_cancel: bool = False, is_modal: bool = False):
        pass  # Replace with actual implementation if needed

    def merge_commands(self, command) -> 'MergeableBackgroundCommand':
        raise NotImplementedError("Method not implemented")
```

Here's a brief explanation of the translation:

1. In Python, we don't have an equivalent to Java's `package` declaration or public abstract class definition.
2. The constructor (`__init__`) in Python is similar to the one in Java but with some differences:
   - We use type hints for the parameters (e.g., `str`, `bool`) which are not enforced at runtime, unlike Java where they would be checked by the compiler.
   - In Python, we don't need a separate method definition for constructors like in Java. The constructor is defined using the special method name (`__init__`).
3. For the abstract mergeCommands() method:
   - We use `def` to define methods instead of `public abstract`.
   - Instead of declaring it as an abstract method, we raise a `NotImplementedError`. This indicates that this method should be implemented in any subclass.
4. The return type for the `merge_commands()` method is annotated with `'MergeableBackgroundCommand'`, which means Python will infer the correct return type based on its implementation.

Please note that you would need to implement the actual logic inside these methods according to your specific requirements.