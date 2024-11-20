Here is the translation of the Java interface into a Python class:

```Python
class DbgModelTargetThreadContainer:
    def get_target_thread(self, thread: 'DbgThread') -> 'DbgModelTargetThread':
        pass  # implement this method in your subclass

    def thread_created(self, thread: 'DbgThread'):
        pass  # implement this method in your subclass

    def thread_exited(self, thread_id: int):
        pass  # implement this method in your subclass
```

Note that the `DbgModelTargetThread`, `DbgThread` and other classes are not defined here. They would need to be implemented separately as Python classes or imported from another module if they already exist.

Also note that Python does not have a direct equivalent of Java interfaces, but it can achieve similar functionality using abstract base classes (ABCs) with abstract methods.