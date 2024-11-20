Here is the translation of the given Java code into Python:

```Python
class DbgStateListener:
    def __init__(self):
        pass

    def state_changed(self, old_state: 'DbgState', new_state: 'DbgState', cause: 'DbgCause'):
        """The state has changed because of the given cause"""
        # Your code here to handle the state change
        pass


class DbgState:
    pass


class DbgCause:
    pass

```

Note that Python does not have direct equivalent for Java's TriConsumer interface. So, I've created a simple class `DbgStateListener` with a method `state_changed`. This method takes three parameters: old state, new state and cause.

Also note that in Python, we don't need to explicitly define the accept() method as it is already handled by the default implementation provided by the built-in function `default()` from the functools module.