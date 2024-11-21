Here is the equivalent Python code:

```
class RelayoutOption:
    ALWAYS = ("Always",)
    BLOCK_MODEL_CHANGES = ("Block Model Changes Only",)
    VERTEX_GROUPING_CHANGES = ("Vertex Grouping Changes Only",)
    NEVER = ("Never",)

    def __init__(self, display_name):
        self.display_name = display_name

    def __str__(self):
        return self.display_name
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we define a class with constant values as tuples or strings. The `__init__` method is used to initialize the object, and the `__str__` method is overridden to provide a string representation of the object.