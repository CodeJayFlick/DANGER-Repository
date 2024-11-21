Here is the translation of the Java interface into a Python class:

```Python
class InvalidatableTargetObject:
    def __init__(self):
        pass

    def invalidate_subtree(self, branch: 'TargetObject', reason: str) -> None:
        """Invalidate this subtree
        
        In most cases, this need only be invoked on the root to destroy the entire model,
        or if the implementation is managing the collections of children. Otherwise,
        change_attributes, change_elements, set_attributes, and set_elements will automatically
        invoke this method when they detect object removal.
        
        :param branch: The root of the sub-tree that is being removed
        :param reason: A human-consumable explanation for the removal
        """
        pass

    def do_invalidate_subtree(self, branch: 'TargetObject', reason: str) -> None:
        """Invalidate this subtree without locking
        
        This really only exists to avoid reentering a lock. This should be called when 
        a thread has already acquired the relevant locks.
        
        :param branch:
        :param reason:
        """
        pass
```

Note that Python does not have direct support for interfaces like Java, so we use classes instead. The `pass` statement is used to indicate that these methods do nothing in this implementation.