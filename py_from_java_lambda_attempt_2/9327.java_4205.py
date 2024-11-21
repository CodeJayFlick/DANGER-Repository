Here's the translation of the Java interface into a Python class:

```Python
class ComponentProviderActivationListener:
    def __init__(self):
        pass

    def component_provider_activated(self, component_provider: 'ComponentProvider'):
        """Called when the given component provider is activated."""
        pass  # Add your implementation here

    def component_provider_deactivated(self, component_provider: 'ComponentProvider'):
        """Called when the given component provider is deactivated."""
        pass  # Add your implementation here
```

Note that Python does not have a direct equivalent to Java's interface. Instead, we define a class with methods that match those in the original interface. The `pass` statements are placeholders for any actual code you might want to add later.