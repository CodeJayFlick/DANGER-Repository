Here is the translation of the Java interface `GTreeFilter` to a Python class:

```python
class GTreeFilter:
    def accepts_node(self, node):
        # implement your logic here
        pass

    def show_filter_matches(self) -> bool:
        return True  # or False depending on your implementation
```

Note that in Python, we don't have an explicit `public` keyword for methods and attributes. Instead, everything is public by default unless it's preceded by a single underscore (`_`) which indicates private access.

Also, the Java method `showFilterMatches()` has been translated to a Python method with the same name, but with parentheses indicating that it returns a boolean value (using the `-> bool` syntax).