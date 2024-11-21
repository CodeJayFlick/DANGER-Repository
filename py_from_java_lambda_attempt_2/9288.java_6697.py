Here is the translation of the Java interface `ComponentBasedDockingAction` into a Python class:

```python
class ComponentBasedDockingAction:
    def __init__(self):
        pass

    def isValid_component_context(self, context: 'ActionContext') -> bool:
        """
        Returns True if the given context contains this action's component.
        
        :param context: The context to check
        :return: Whether the given context contains this action's component
        """
        # TO DO: implement your logic here
        pass

class ActionContext:
    def __init__(self):
        pass
```

Note that I've used Python 3.6+ syntax for type hints, and also defined a separate `ActionContext` class as it seems to be an interface in the original Java code.