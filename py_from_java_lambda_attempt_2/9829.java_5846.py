Here's the translation of the given Java interface into a Python class:

```Python
class ObjectSelectedListener:
    def __init__(self):
        pass

    def object_selected(self, t=None):
        """
        When an object is selected; None if the selection is cleared
        
        :param t: The object selected or None
        """
        pass  # Implement this method in your subclass
```

In Python, we don't have direct support for generic types like Java's `<T>`. So I've removed that part. Also, note that `pass` statements are used to indicate the absence of a statement; you would need to implement the `object_selected` method according to your needs in any subclass.