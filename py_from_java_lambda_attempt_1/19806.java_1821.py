Here's your Java code translated into equivalent Python:

```Python
class SelfRegisteringSkriptEvent:
    def __init__(self):
        pass
    
    def register(self, t):
        # This method is called after the whole trigger is loaded for events that fire themselves.
        # This is also called when the script is deserialised.
        raise NotImplementedError("register must be implemented")

    def unregister(self, t):
        # This method is called to unregister this event registered through register(Trigger).
        raise NotImplementedError("unregister must be implemented")

    def unregister_all(self):
        # This method is called to unregister all events registered through register(Trigger). 
        # This is called on all registered events, thus it can also only unregister the
        # event it is called on.
        raise NotImplementedError("unregister_all must be implemented")
    
    def check(self, e):
        # This method is called when this event is parsed. Overriding this is
        # optional, and usually not needed.
        raise UnsupportedOperationException()

    def after_parse(self, config):
        pass

# Note: Python does not have a direct equivalent to Java's abstract classes or methods,
# so we just implement the check() method here as it would be in any other class. The register(),
# unregister(), and unregister_all() methods are implemented with NotImplementedError
```

Please note that this is an approximate translation, since there isn't a direct Python equivalent for some of these Java concepts (like abstract classes or methods).