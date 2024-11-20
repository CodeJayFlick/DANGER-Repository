Here's the translation:

```
class ComponentLoadedListener:
    def __init__(self):
        pass

    def component_loaded(self, window_manager: object, provider: object) -> None:
        """
        Called when the component is made displayable
        
        :param window_manager: The window manager associated with the loaded component; null if 
            the component for this listener is not parented by a docking window manager
        :type window_manager: object
        :param provider: The provider that is the parent of the given component; null if 
            the component for this listener is not the child of a component provider
        :type provider: object
        """
        pass

# Note: Python does not have direct equivalent to Java's interface. It uses abstract base classes (ABCs) or protocols.
```

Note that I've used type hints (`-> None` and `object`) for clarity, but they are not enforced by the interpreter.