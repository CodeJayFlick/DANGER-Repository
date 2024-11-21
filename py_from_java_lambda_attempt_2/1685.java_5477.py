Here is the translation of the Java interface `LldbModelTargetSessionContainer` to a Python class:

```python
class LldbModelTargetSessionContainer:
    def __init__(self):
        pass

    def session_added(self, session: 'SBTarget', cause: 'LldbCause'):
        # implement this method in your subclass
        raise NotImplementedError("session_added not implemented")

    def session_replaced(self, session: 'SBTarget', cause: 'LldbCause'):
        # implement this method in your subclass
        raise NotImplementedError("session_replaced not implemented")

    def session_removed(self, sessionId: str, cause: 'LldbCause'):
        # implement this method in your subclass
        raise NotImplementedError("session_removed not implemented")

    def get_target_session(self, session: 'SBTarget') -> 'LldbModelTargetSession':
        # implement this method in your subclass
        raise NotImplementedError("get_target_session not implemented")
```

Note that I've used the `NotImplementedError` exception to indicate that these methods are abstract and must be implemented by a concrete subclass.