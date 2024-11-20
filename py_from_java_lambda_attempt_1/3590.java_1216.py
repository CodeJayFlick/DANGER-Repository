Here is the translation of the Java interface `EditorModelListener` to a Python class:

```python
class EditorModelListener:
    EDIT_STARTED = 5
    EDIT_ENDED = 6

    def edit_state_changed(self, type):
        pass
```

Note that in Python, we don't have an equivalent concept to Java's interfaces. Instead, we can define a class with methods that are intended to be implemented by subclasses or used as is. In this case, I've defined the `EditorModelListener` class with two constants and one method (`edit_state_changed`). The method takes a single argument `type`, which corresponds to the `int type` parameter in the Java interface.