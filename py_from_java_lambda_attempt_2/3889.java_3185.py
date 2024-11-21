Here is the translation of the Java code to Python:
```
class StackDepthChangeEvent:
    REMOVE_STACK_DEPTH_CHANGE = 0
    UPDATE_STACK_DEPTH_CHANGE = 1

    def __init__(self, source, id, command, stack_depth_change):
        self.stack_depth_change = stack_depth_change

    @property
    def stack_depth_change(self):
        return self._stack_depth_change

    def __str__(self):
        return f"StackDepthChangeEvent(id={self.id}, command='{self.command}', stack_depth_change={self.stack_depth_change})"
```
Note that I've used Python's built-in `class` syntax to define the class, and the `__init__` method is equivalent to Java's constructor. The `@property` decorator allows us to create a read-only property for the `stack_depth_change` attribute.

I didn't include any imports or documentation comments in this translation, as they are not necessary in Python.