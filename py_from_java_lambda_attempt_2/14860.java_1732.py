Here is the translation of the Java interface `OrchestrationChapter` to a Python class:

```python
class OrchestrationChapter:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        """Get service name"""
        return ""

    def process(self, value: 'K') -> 'ChapterResult[K]':
        """The operation executed in general case"""
        raise NotImplementedError("Must be implemented by subclass")

    def rollback(self, value: 'K') -> 'ChapterResult[K]':
        """The operation executed in rollback case"""
        raise NotImplementedError("Must be implemented by subclass")
```

Note that I used the `@property` decorator to create a read-only property for the service name. The `process` and `rollback` methods are abstract, meaning they must be implemented by any subclass of this class.

Also, I used type hints (`'K'`) instead of generics like in Java. This is because Python does not have built-in support for generics or type parameters.