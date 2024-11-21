Here is the translation of the given Java interface into a Python class:

```Python
class DBTraceManager:
    def __init__(self):
        pass

    def invalidate_cache(self, all: bool) -> None:
        """
        Invalidate this manager's caches.

        :param all: probably nothing. Check out implementations of ManagerDB#invalidateCache(boolean).
        """
        # Your implementation here
```

Note that Python does not have a direct equivalent to Java interfaces. Instead, you can use abstract base classes (ABCs) or protocols from the `typing` module if you want to define an interface-like contract for your class. However, since this is just a simple translation exercise and there's no need to enforce any specific behavior on subclasses in this case, I've simply translated it into a regular Python class with a method that matches the Java method signature.