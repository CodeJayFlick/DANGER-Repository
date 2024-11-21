Here is the translation of the Java interface `CheckinHandler` to a Python class:

```python
class CheckinHandler:
    def get_comment(self) -> str:
        # Implement your logic here
        pass  # Replace with actual implementation

    def keep_checked_out(self) -> bool:
        # Implement your logic here
        return False  # Default value, replace with actual implementation

    def create_keep_file(self) -> bool:
        # Implement your logic here
        return False  # Default value, replace with actual implementation
```

Note that I've kept the method signatures similar to the original Java interface. In Python, we don't need explicit `throws` clauses for exceptions like `CancelledException`, as Python's exception handling mechanism is different from Java's.

You'll need to implement the logic inside each method according to your specific requirements.